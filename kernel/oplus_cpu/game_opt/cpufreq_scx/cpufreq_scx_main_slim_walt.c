// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */
#include <linux/kmemleak.h>
#include <linux/cpufreq.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <../kernel/sched/sched.h>
#include <../kernel/sched/hmbird/hmbird_sched.h>
#include <trace/hooks/sched.h>

#include "../cpufreq_scx_main.h"

unsigned int sysctl_scx_gov_debug;
static int cpufreq_gov_debug(void) {return sysctl_scx_gov_debug;}

/*debug level for scx_gov*/
#define DEBUG_SYSTRACE (1 << 0)
#define DEBUG_FTRACE   (1 << 1)
#define DEBUG_KMSG     (1 << 2)

#define scx_gov_debug(fmt, ...) \
	pr_info("[scx_gov][%s] "fmt, __func__, ##__VA_ARGS__)

#define scx_gov_err(fmt, ...) \
	pr_err("[scx_gov][%s] "fmt, __func__, ##__VA_ARGS__)

#define gov_trace_printk(fmt, args...)	\
do {										\
		trace_printk("[scx_gov] "fmt, args);	\
} while (0)

#define DEFAULT_TARGET_LOAD 90

#define MAX_CLUSTERS 4
static int gov_flag[MAX_CLUSTERS] = {0};
struct proc_dir_entry *dir;
struct scx_sched_cluster {
	struct list_head	list;
	struct cpumask	cpus;
	int id;
};
__read_mostly int num_sched_clusters;
#define MAX_CLS_NUM 5
#define HMBIRD_TICK_HIT_BOOST		BIT(29)
struct scx_sched_cluster *scx_cluster[MAX_CLS_NUM];
struct list_head cluster_head;
atomic_t tick_hit_boost_protect = ATOMIC_INIT(0);
int tick_hit_boost_cpu = -1;
#define for_each_sched_cluster(cluster) \
	list_for_each_entry_rcu(cluster, &cluster_head, list)

struct scx_gov_tunables {
	struct gov_attr_set		attr_set;
	unsigned int			target_loads;
	int				soft_freq_max;
	int				soft_freq_min;
	bool				apply_freq_immediately;
};

struct scx_gov_policy {
	struct cpufreq_policy	*policy;

	struct scx_gov_tunables	*tunables;
	struct list_head	tunables_hook;

	raw_spinlock_t		update_lock;	/* For shared policies */
	unsigned int		next_freq;
	unsigned int		freq_cached;
	/* The next fields are only needed if fast switch cannot be used: */
	struct kthread_work	work;
	struct mutex		work_lock;
	struct kthread_worker	worker;
	struct task_struct	*thread;
	bool			work_in_progress;
	unsigned int	target_load;
	bool		backup_efficiencies_available;
};

struct scx_gov_cpu {
	struct update_util_data	update_util;
	unsigned int		reasons;
	struct scx_gov_policy	*sg_policy;
	unsigned int		cpu;

	unsigned long		util;
	unsigned int		flags;
};

static DEFINE_PER_CPU(struct scx_gov_cpu, scx_gov_cpu);
static DEFINE_PER_CPU(struct scx_gov_tunables *, cached_tunables);
static DEFINE_MUTEX(global_tunables_lock);
static struct scx_gov_tunables *global_tunables;

static void scx_gov_work(struct kthread_work *work)
{
	struct scx_gov_policy *sg_policy = container_of(work, struct scx_gov_policy, work);
	unsigned int freq;
	unsigned long flags;

	/*
	 * Hold sg_policy->update_lock shortly to handle the case where:
	 * incase sg_policy->next_freq is read here, and then updated by
	 * scx_gov_deferred_update() just before work_in_progress is set to false
	 * here, we may miss queueing the new update.
	 *
	 * Note: If a work was queued after the update_lock is released,
	 * scx_gov_work() will just be called again by kthread_work code; and the
	 * request will be proceed before the scx_gov thread sleeps.
	 */
	raw_spin_lock_irqsave(&sg_policy->update_lock, flags);
	freq = sg_policy->next_freq;
	raw_spin_unlock_irqrestore(&sg_policy->update_lock, flags);

	mutex_lock(&sg_policy->work_lock);
	__cpufreq_driver_target(sg_policy->policy, freq, CPUFREQ_RELATION_L);
	mutex_unlock(&sg_policy->work_lock);
}

/* next_freq = (max_freq * scale_time* 100)/(window_size * TL * arch_scale_cpu_capacity) */
#define DIV64_U64_ROUNDUP(X, Y) div64_u64((X) + (Y - 1), Y)
static unsigned int get_next_freq(struct scx_gov_policy *sg_policy, u64 prev_runnable_sum)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned int freq = policy->cpuinfo.max_freq, next_f;
	unsigned int window_size_tl, cluster_tl;
	u64 divisor;
	int cpu = cpumask_first(policy->cpus);

	struct rq *rq;
	struct hmbird_sched_rq_stats *srq;
	int *scx_sched_ravg_window_ptr;

	cluster_tl = DEFAULT_TARGET_LOAD;
	if (sg_policy->tunables) {
		cluster_tl = sg_policy->tunables->target_loads;
	}

	rq = cpu_rq(cpu);
	srq = get_hmbird_rq(rq)->srq;
	scx_sched_ravg_window_ptr = srq->sched_ravg_window_ptr;

	window_size_tl = mult_frac(*scx_sched_ravg_window_ptr, cluster_tl, 100);

	divisor = DIV64_U64_ROUNDUP(window_size_tl * arch_scale_cpu_capacity(cpu), freq);
	next_f = DIV64_U64_ROUNDUP(prev_runnable_sum << SCHED_CAPACITY_SHIFT, divisor);

	if (cpufreq_gov_debug() & DEBUG_FTRACE)
		gov_trace_printk("cluster[%d] max_freq[%d] win_tl[%d] cpu_cap[%lu] divisor[%llu] next_f[%d]\n",
			cpu, freq, window_size_tl, arch_scale_cpu_capacity(cpu), divisor, next_f);
	return next_f;
}

static unsigned int soft_freq_clamp(struct scx_gov_policy *sg_policy, unsigned int target_freq)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	int soft_freq_max = sg_policy->tunables->soft_freq_max;
	int soft_freq_min = sg_policy->tunables->soft_freq_min;

	if (soft_freq_min >= 0 && soft_freq_min > target_freq) {
		target_freq = soft_freq_min;
	}
	if (soft_freq_max >= 0 && soft_freq_max < target_freq) {
		target_freq = soft_freq_max;
	}

	if (cpufreq_gov_debug() & DEBUG_FTRACE)
		gov_trace_printk("cluster[%d] max_freq[%d] min_freq[%d] freq[%d]\n",
			policy->cpu, soft_freq_max, soft_freq_min, target_freq);

	return target_freq;
}

void scx_gov_update_cpufreq(struct cpufreq_policy *policy, u64 prev_runnable_sum)
{
	unsigned int next_f;
	struct scx_gov_policy *sg_policy = policy->governor_data;
	unsigned long irq_flags;

	raw_spin_lock_irqsave(&sg_policy->update_lock, irq_flags);

	next_f = get_next_freq(sg_policy, prev_runnable_sum);
	next_f = soft_freq_clamp(sg_policy, next_f);
	next_f = cpufreq_driver_resolve_freq(policy, next_f);
	sg_policy->freq_cached = sg_policy->next_freq ? sg_policy->next_freq : next_f;
	if (sg_policy->next_freq == next_f)
		goto unlock;
	sg_policy->next_freq = next_f;
	if (cpufreq_gov_debug() & DEBUG_FTRACE)
		gov_trace_printk("cluster[%d] freq[%d] fast[%d]\n", policy->cpu, next_f, policy->fast_switch_enabled);
	if (policy->fast_switch_enabled)
		cpufreq_driver_fast_switch(policy, next_f);
	else
		kthread_queue_work(&sg_policy->worker, &sg_policy->work);

unlock:
	raw_spin_unlock_irqrestore(&sg_policy->update_lock, irq_flags);
}

void scx_gov_update_soft_limit_cpufreq(struct scx_gov_policy *sg_policy)
{
	unsigned int next_f;
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned long irq_flags;

	raw_spin_lock_irqsave(&sg_policy->update_lock, irq_flags);

	next_f = soft_freq_clamp(sg_policy, sg_policy->next_freq);
	next_f = cpufreq_driver_resolve_freq(policy, next_f);
	if (sg_policy->next_freq == next_f)
		goto unlock;
	sg_policy->next_freq = next_f;
	if (cpufreq_gov_debug() & DEBUG_FTRACE)
		gov_trace_printk("cluster[%d] freq[%d] fast[%d]\n",
			policy->cpu, next_f, policy->fast_switch_enabled);
	if (policy->fast_switch_enabled)
		cpufreq_driver_fast_switch(policy, next_f);
	else
		kthread_queue_work(&sg_policy->worker, &sg_policy->work);

unlock:
	raw_spin_unlock_irqrestore(&sg_policy->update_lock, irq_flags);
}

/************************** sysfs interface ************************/
static inline struct scx_gov_tunables *to_scx_gov_tunables(struct gov_attr_set *attr_set)
{
	return container_of(attr_set, struct scx_gov_tunables, attr_set);
}

static DEFINE_MUTEX(min_rate_lock);


static ssize_t target_loads_show(struct gov_attr_set *attr_set, char *buf)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	return sprintf(buf, "%d\n", tunables->target_loads);
}

static ssize_t target_loads_store(struct gov_attr_set *attr_set, const char *buf,
					size_t count)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	unsigned int new_target_loads = DEFAULT_TARGET_LOAD;

	if (kstrtouint(buf, 10, &new_target_loads))
		return -EINVAL;

	tunables->target_loads = new_target_loads;
	return count;
}

static ssize_t soft_freq_max_show(struct gov_attr_set *attr_set, char *buf)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	int soft_freq_max = tunables->soft_freq_max;

	if (soft_freq_max < 0) {
		return sprintf(buf, "max\n");
	} else {
		return sprintf(buf, "%d\n", soft_freq_max);
	}
}

static ssize_t soft_freq_max_store(struct gov_attr_set *attr_set, const char *buf, size_t count)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	struct scx_gov_policy *sg_policy = list_first_entry(&attr_set->policy_list, struct scx_gov_policy, tunables_hook);
	int new_soft_freq_max = -1;

	if (kstrtoint(buf, 10, &new_soft_freq_max))
		return -EINVAL;

	if (tunables->soft_freq_max == new_soft_freq_max) {
		return count;
	}

	tunables->soft_freq_max = new_soft_freq_max;
	if (tunables->apply_freq_immediately) {
		scx_gov_update_soft_limit_cpufreq(sg_policy);
	}

	return count;
}

static ssize_t soft_freq_min_show(struct gov_attr_set *attr_set, char *buf)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	int soft_freq_min = tunables->soft_freq_min;

	if (soft_freq_min < 0) {
		return sprintf(buf, "0\n");
	} else {
		return sprintf(buf, "%d\n", soft_freq_min);
	}
}

static ssize_t soft_freq_min_store(struct gov_attr_set *attr_set, const char *buf, size_t count)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	struct scx_gov_policy *sg_policy = list_first_entry(&attr_set->policy_list, struct scx_gov_policy, tunables_hook);
	int new_soft_freq_min = -1;

	if (kstrtoint(buf, 10, &new_soft_freq_min))
		return -EINVAL;

	if (tunables->soft_freq_min == new_soft_freq_min) {
		return count;
	}

	tunables->soft_freq_min = new_soft_freq_min;
	if (tunables->apply_freq_immediately) {
		scx_gov_update_soft_limit_cpufreq(sg_policy);
	}

	return count;
}

static ssize_t soft_freq_cur_show(struct gov_attr_set *attr_set __maybe_unused, char *buf)
{
	return sprintf(buf, "none\n");
}

static ssize_t soft_freq_cur_store(struct gov_attr_set *attr_set, const char *buf, size_t count)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	struct scx_gov_policy *sg_policy = list_first_entry(&attr_set->policy_list, struct scx_gov_policy, tunables_hook);
	int new_soft_freq_cur = -1;

	if (kstrtoint(buf, 10, &new_soft_freq_cur))
		return -EINVAL;

	if (tunables->soft_freq_max == new_soft_freq_cur && tunables->soft_freq_min == new_soft_freq_cur) {
		return count;
	}

	tunables->soft_freq_max = new_soft_freq_cur;
	tunables->soft_freq_min = new_soft_freq_cur;
	if (tunables->apply_freq_immediately) {
		scx_gov_update_soft_limit_cpufreq(sg_policy);
	}

	return count;
}

static ssize_t apply_freq_immediately_show(struct gov_attr_set *attr_set, char *buf)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	return sprintf(buf, "%d\n", (int)tunables->apply_freq_immediately);
}

static ssize_t apply_freq_immediately_store(struct gov_attr_set *attr_set, const char *buf, size_t count)
{
	struct scx_gov_tunables *tunables = to_scx_gov_tunables(attr_set);
	int new_apply_freq_immediately = 0;

	if (kstrtoint(buf, 10, &new_apply_freq_immediately))
		return -EINVAL;

	tunables->apply_freq_immediately = new_apply_freq_immediately > 0;
	return count;
}

static struct governor_attr target_loads =
	__ATTR(target_loads, 0664, target_loads_show, target_loads_store);

static struct governor_attr soft_freq_max =
	__ATTR(soft_freq_max, 0664, soft_freq_max_show, soft_freq_max_store);

static struct governor_attr soft_freq_min =
	__ATTR(soft_freq_min, 0664, soft_freq_min_show, soft_freq_min_store);

static struct governor_attr soft_freq_cur =
	__ATTR(soft_freq_cur, 0664, soft_freq_cur_show, soft_freq_cur_store);

static struct governor_attr apply_freq_immediately =
	__ATTR(apply_freq_immediately, 0664, apply_freq_immediately_show, apply_freq_immediately_store);

static struct attribute *scx_gov_attrs[] = {
	&target_loads.attr,
	&soft_freq_max.attr,
	&soft_freq_min.attr,
	&soft_freq_cur.attr,
	&apply_freq_immediately.attr,
	NULL
};
ATTRIBUTE_GROUPS(scx_gov);

static struct kobj_type scx_gov_tunables_ktype = {
	.default_groups = scx_gov_groups,
	.sysfs_ops = &governor_sysfs_ops,
};

/********************** cpufreq governor interface *********************/

struct cpufreq_governor cpufreq_scx_gov;

static struct scx_gov_policy *scx_gov_policy_alloc(struct cpufreq_policy *policy)
{
	struct scx_gov_policy *sg_policy;

	sg_policy = kzalloc(sizeof(*sg_policy), GFP_KERNEL);
	if (!sg_policy)
		return NULL;

	sg_policy->policy = policy;
	raw_spin_lock_init(&sg_policy->update_lock);
	return sg_policy;
}

static inline void scx_gov_cpu_reset(struct scx_gov_policy *sg_policy)
{
	unsigned int cpu;

	for_each_cpu(cpu, sg_policy->policy->cpus) {
		struct scx_gov_cpu *sg_cpu = &per_cpu(scx_gov_cpu, cpu);

		sg_cpu->sg_policy = NULL;
	}
}

static void scx_gov_policy_free(struct scx_gov_policy *sg_policy)
{
	kfree(sg_policy);
}

static void scxgov_update_freq(struct update_util_data *cb, u64 time, unsigned int flags)
{
	struct scx_gov_cpu *sg_cpu = container_of(cb, struct scx_gov_cpu, update_util);
	struct hmbird_ops *hmbird_ops = get_hmbird_ops(this_rq());
	struct scx_sched_cluster *cluster;
	struct cpufreq_policy *policy;
	struct scx_gov_policy *sg_policy;
	struct hmbird_sched_rq_stats *srq;
	struct rq *rq;
	int cpu;
	unsigned long irq_flags;
	unsigned int next_f;

	if (flags & HMBIRD_CPUFREQ_WINDOW_ROLLOVER) {
		for_each_sched_cluster(cluster) {
			cpumask_t cluster_online_cpus;
			u64 prev_runnable_sum = 0;
			if (gov_flag[cluster->id] == 0)
				continue;
			cpumask_and(&cluster_online_cpus, &cluster->cpus, cpu_online_mask);
			if (atomic_read(&tick_hit_boost_protect)) {
				if (cpumask_test_cpu(tick_hit_boost_cpu, &cluster->cpus)) {
					atomic_set(&tick_hit_boost_protect, 0);
					tick_hit_boost_cpu = -1;
					continue;
				}
			}
			for_each_cpu(cpu, &cluster_online_cpus) {
				rq = cpu_rq(cpu);
				srq = get_hmbird_rq(rq)->srq;
				if (cpufreq_gov_debug() & DEBUG_FTRACE)
					gov_trace_printk("cpu[%d] prev_runnable_sum[%llu]\n", cpu, srq->prev_runnable_sum);
				prev_runnable_sum = max(prev_runnable_sum, srq->prev_runnable_sum);
			}

			policy = cpufreq_cpu_get_raw(cpumask_first(&cluster_online_cpus));
			if (policy == NULL)
				scx_gov_err("NULL policy [%d]\n", cpumask_first(&cluster_online_cpus));
			scx_gov_update_cpufreq(policy, prev_runnable_sum);
		}
	}

	if ((flags & HMBIRD_TICK_HIT_BOOST)) {
		int boost_enable = hmbird_ops->hmbird_get_boost_enable();
		unsigned int boost_bottom_freq = hmbird_ops->hmbird_get_boost_bottom_freq();
		int boost_weight = hmbird_ops->hmbird_get_boost_weight();
		int cluster_id = topology_cluster_id(sg_cpu->cpu);
		if (!boost_enable)
			return;
		if (gov_flag[cluster_id] == 0)
			return;
		policy = cpufreq_cpu_get_raw(sg_cpu->cpu);
		sg_policy = policy->governor_data;
		raw_spin_lock_irqsave(&sg_policy->update_lock, irq_flags);
		if (sg_policy->next_freq <= boost_bottom_freq) {
			next_f = boost_bottom_freq;
		} else {
			next_f = mult_frac(sg_policy->next_freq, boost_weight, 100);
		}
		next_f = soft_freq_clamp(sg_policy, next_f);
		next_f = cpufreq_driver_resolve_freq(policy, next_f);
		if (sg_policy->next_freq == next_f)
			goto unlock;
		sg_policy->next_freq = next_f;
		gov_trace_printk("cluster[%d] freq[%d] fast[%d]\n",
				policy->cpu, next_f, policy->fast_switch_enabled);
		atomic_set(&tick_hit_boost_protect, 1);
		tick_hit_boost_cpu = sg_cpu->cpu;
		if (policy->fast_switch_enabled)
			cpufreq_driver_fast_switch(policy, next_f);
		else
			kthread_queue_work(&sg_policy->worker, &sg_policy->work);

unlock:
		raw_spin_unlock_irqrestore(&sg_policy->update_lock, irq_flags);
	}
}

static int scx_gov_kthread_create(struct scx_gov_policy *sg_policy)
{
	struct task_struct *thread;
	struct sched_attr attr = {
		.size		= sizeof(struct sched_attr),
		.sched_policy	= SCHED_DEADLINE,
		.sched_flags	= SCHED_FLAG_SUGOV,
		.sched_nice	= 0,
		.sched_priority	= 0,
		/*
		 * Fake (unused) bandwidth; workaround to "fix"
		 * priority inheritance.
		 */
		.sched_runtime	=  1000000,
		.sched_deadline = 10000000,
		.sched_period	= 10000000,
	};
	struct cpufreq_policy *policy = sg_policy->policy;
	int ret;

	/* kthread only required for slow path */
	if (policy->fast_switch_enabled)
		return 0;

	kthread_init_work(&sg_policy->work, scx_gov_work);
	kthread_init_worker(&sg_policy->worker);
	thread = kthread_create(kthread_worker_fn, &sg_policy->worker,
				"scx_gov:%d",
				cpumask_first(policy->related_cpus));
	if (IS_ERR(thread)) {
		pr_err("failed to create scx_gov thread: %ld\n", PTR_ERR(thread));
		return PTR_ERR(thread);
	}

	ret = sched_setattr_nocheck(thread, &attr);
	if (ret) {
		kthread_stop(thread);
		pr_warn("%s: failed to set SCHED_DEADLINE\n", __func__);
		return ret;
	}

	sg_policy->thread = thread;
	kthread_bind_mask(thread, policy->related_cpus);
	mutex_init(&sg_policy->work_lock);

	wake_up_process(thread);

	return 0;
}

static void scx_gov_kthread_stop(struct scx_gov_policy *sg_policy)
{
	/* kthread only required for slow path */
	if (sg_policy->policy->fast_switch_enabled)
		return;

	kthread_flush_worker(&sg_policy->worker);
	kthread_stop(sg_policy->thread);
	mutex_destroy(&sg_policy->work_lock);
}

static struct scx_gov_tunables *scx_gov_tunables_alloc(struct scx_gov_policy *sg_policy)
{
	struct scx_gov_tunables *tunables;

	tunables = kzalloc(sizeof(*tunables), GFP_KERNEL);
	if (tunables) {
		gov_attr_set_init(&tunables->attr_set, &sg_policy->tunables_hook);
		if (!have_governor_per_policy())
			global_tunables = tunables;
	}
	return tunables;
}

static void scx_gov_tunables_free(struct scx_gov_tunables *tunables)
{
	if (!have_governor_per_policy())
		global_tunables = NULL;

	kfree(tunables);
}

#define DEFAULT_HISPEED_LOAD 90
static void scx_gov_tunables_save(struct cpufreq_policy *policy,
		struct scx_gov_tunables *tunables)
{
	int cpu;
	struct scx_gov_tunables *cached = per_cpu(cached_tunables, policy->cpu);

	if (!cached) {
		cached = kzalloc(sizeof(*tunables), GFP_KERNEL);
		if (!cached)
			return;

		for_each_cpu(cpu, policy->related_cpus)
			per_cpu(cached_tunables, cpu) = cached;
	}
}

/*********************************
 * rebuild scx cluster
 *********************************/

static inline void move_list(struct list_head *dst, struct list_head *src)
{
	struct list_head *first, *last;

	first = src->next;
	last = src->prev;

	first->prev = dst;
	dst->prev = last;
	last->next = dst;

	/* Ensure list sanity before making the head visible to all CPUs. */
	smp_mb();
	dst->next = first;
}

static void get_possible_siblings(int cpuid, struct cpumask *cluster_cpus)
{
	int cpu;
	struct cpu_topology *cpu_topo, *cpuid_topo = &cpu_topology[cpuid];

	if (cpuid_topo->cluster_id == -1)
		return;

	for_each_possible_cpu(cpu) {
		cpu_topo = &cpu_topology[cpu];

		if (cpuid_topo->cluster_id != cpu_topo->cluster_id)
			continue;
		cpumask_set_cpu(cpu, cluster_cpus);
	}
}

static void insert_cluster(struct scx_sched_cluster *cluster, struct list_head *head)
{
	struct scx_sched_cluster *tmp;
	struct list_head *iter = head;

	list_for_each_entry(tmp, head, list) {
		if (arch_scale_cpu_capacity(cpumask_first(&cluster->cpus))
			< arch_scale_cpu_capacity(cpumask_first(&tmp->cpus)))
			break;
		iter = &tmp->list;
	}

	list_add(&cluster->list, iter);
}

static void cleanup_clusters(struct list_head *head)
{
	struct scx_sched_cluster *cluster, *tmp;

	list_for_each_entry_safe(cluster, tmp, head, list) {
		list_del(&cluster->list);
		num_sched_clusters--;
		kfree(cluster);
	}
}

static struct scx_sched_cluster *alloc_new_cluster(const struct cpumask *cpus)
{
	struct scx_sched_cluster *cluster = NULL;

	cluster = kzalloc(sizeof(struct scx_sched_cluster), GFP_ATOMIC);

	INIT_LIST_HEAD(&cluster->list);
	cluster->cpus = *cpus;

	return cluster;
}

static inline void add_cluster(const struct cpumask *cpus, struct list_head *head)
{
	struct scx_sched_cluster *cluster = NULL;

	cluster = alloc_new_cluster(cpus);
	insert_cluster(cluster, head);

	scx_cluster[num_sched_clusters] = cluster;

	num_sched_clusters++;
}

static inline void assign_cluster_ids(struct list_head *head)
{
	struct scx_sched_cluster *cluster;
	unsigned int cpu;

	list_for_each_entry(cluster, head, list) {
		cpu = cpumask_first(&cluster->cpus);
		cluster->id = topology_cluster_id(cpu);
		scx_gov_debug("assign cluster[%d] cluster_id[%d]\n", cpu, cluster->id);
	}
}

static bool scx_build_clusters(void)
{
	struct cpumask cpus = *cpu_possible_mask;
	struct cpumask cluster_cpus;
	struct list_head new_head;
	int i;

	INIT_LIST_HEAD(&cluster_head);
	INIT_LIST_HEAD(&new_head);

	/* If this work failed, our cluster_head can still used with only one cluster struct */
	for_each_cpu(i, &cpus) {
		cpumask_clear(&cluster_cpus);
		get_possible_siblings(i, &cluster_cpus);
		if (cpumask_empty(&cluster_cpus)) {
			cleanup_clusters(&new_head);
			return false;
		}
		cpumask_andnot(&cpus, &cpus, &cluster_cpus);
		add_cluster(&cluster_cpus, &new_head);
	}

	assign_cluster_ids(&new_head);
	move_list(&cluster_head, &new_head);
	return true;
}
/*********************************
 * rebuild scx cluster done
 *********************************/

static int scx_gov_init(struct cpufreq_policy *policy)
{
	struct scx_gov_policy *sg_policy;
	struct scx_gov_tunables *tunables;
	int ret = 0;

	/* State should be equivalent to EXIT */
	if (policy->governor_data)
		return -EBUSY;

	cpufreq_enable_fast_switch(policy);

	sg_policy = scx_gov_policy_alloc(policy);
	if (!sg_policy) {
		ret = -ENOMEM;
		goto disable_fast_switch;
	}

	ret = scx_gov_kthread_create(sg_policy);
	if (ret)
		goto free_sg_policy;

	mutex_lock(&global_tunables_lock);

	if (global_tunables) {
		if (WARN_ON(have_governor_per_policy())) {
			ret = -EINVAL;
			goto stop_kthread;
		}
		policy->governor_data = sg_policy;
		sg_policy->tunables = global_tunables;

		gov_attr_set_get(&global_tunables->attr_set, &sg_policy->tunables_hook);
		goto out;
	}

	tunables = scx_gov_tunables_alloc(sg_policy);
	if (!tunables) {
		ret = -ENOMEM;
		goto stop_kthread;
	}

	tunables->target_loads = DEFAULT_TARGET_LOAD;
	tunables->soft_freq_max = -1;
	tunables->soft_freq_min = -1;
	tunables->apply_freq_immediately = true;

	policy->governor_data = sg_policy;
	sg_policy->tunables = tunables;

	ret = kobject_init_and_add(&tunables->attr_set.kobj, &scx_gov_tunables_ktype,
				   get_governor_parent_kobj(policy), "%s",
				   cpufreq_scx_gov.name);
	if (ret)
		goto fail;

	policy->dvfs_possible_from_any_cpu = 1;

out:
	mutex_unlock(&global_tunables_lock);
	return 0;

fail:
	kobject_put(&tunables->attr_set.kobj);
	policy->governor_data = NULL;
	scx_gov_tunables_free(tunables);

stop_kthread:
	scx_gov_kthread_stop(sg_policy);
	mutex_unlock(&global_tunables_lock);

free_sg_policy:
	scx_gov_policy_free(sg_policy);

disable_fast_switch:
	cpufreq_disable_fast_switch(policy);

	pr_err("initialization failed (error %d)\n", ret);
	return ret;
}

static void scx_gov_exit(struct cpufreq_policy *policy)
{
	struct scx_gov_policy *sg_policy = policy->governor_data;
	struct scx_gov_tunables *tunables = sg_policy->tunables;
	unsigned int count;

	mutex_lock(&global_tunables_lock);

	count = gov_attr_set_put(&tunables->attr_set, &sg_policy->tunables_hook);
	policy->governor_data = NULL;
	if (!count) {
		scx_gov_tunables_save(policy, tunables);
		scx_gov_tunables_free(tunables);
	}

	mutex_unlock(&global_tunables_lock);

	scx_gov_kthread_stop(sg_policy);
	scx_gov_cpu_reset(sg_policy);
	scx_gov_policy_free(sg_policy);
	cpufreq_disable_fast_switch(policy);
}

static int scx_gov_start(struct cpufreq_policy *policy)
{
	struct scx_gov_policy *sg_policy = policy->governor_data;
	unsigned int cpu, cluster_id;

	sg_policy->next_freq = 0;

	for_each_cpu(cpu, policy->cpus) {
		struct scx_gov_cpu *sg_cpu = &per_cpu(scx_gov_cpu, cpu);

		memset(sg_cpu, 0, sizeof(*sg_cpu));
		sg_cpu->cpu			= cpu;
		sg_cpu->sg_policy		= sg_policy;
		cpufreq_add_update_util_hook(cpu, &sg_cpu->update_util, scxgov_update_freq);
	}
	cpu = cpumask_first(policy->related_cpus);
	cluster_id = topology_cluster_id(cpu);
	scx_gov_debug("start cluster[%d] cluster_id[%d] gov\n", cpu, cluster_id);

	/* backup efficiencies_available, set scx efficiencies_available is false*/
	sg_policy->backup_efficiencies_available = policy->efficiencies_available;
	policy->efficiencies_available = false;

	if (cluster_id < MAX_CLUSTERS)
		gov_flag[cluster_id] = 1;

	return 0;
}

static void scx_gov_stop(struct cpufreq_policy *policy)
{
	struct scx_gov_policy *sg_policy = policy->governor_data;
	unsigned int cpu, cluster_id;

	for_each_cpu(cpu, policy->cpus)
		cpufreq_remove_update_util_hook(cpu);

	if (!policy->fast_switch_enabled) {
		kthread_cancel_work_sync(&sg_policy->work);
	}

	/* restore efficiencies_available */
	policy->efficiencies_available = sg_policy->backup_efficiencies_available;

	cpu = cpumask_first(policy->related_cpus);
	cluster_id = topology_cluster_id(cpu);
	if (cluster_id < MAX_CLUSTERS)
		gov_flag[cluster_id] = 0;
	synchronize_rcu();
}

static void scx_gov_limits(struct cpufreq_policy *policy)
{
	struct scx_gov_policy *sg_policy = policy->governor_data;
	unsigned long flags, now;
	unsigned int freq, final_freq;

	if (!policy->fast_switch_enabled) {
		mutex_lock(&sg_policy->work_lock);
		cpufreq_policy_apply_limits(policy);
		mutex_unlock(&sg_policy->work_lock);
	} else {
		raw_spin_lock_irqsave(&sg_policy->update_lock, flags);

		freq = sg_policy->next_freq;
		now = ktime_get_ns();

		final_freq = cpufreq_driver_resolve_freq(policy, freq);
		cpufreq_driver_fast_switch(policy, final_freq);

		raw_spin_unlock_irqrestore(&sg_policy->update_lock, flags);
	}
}

struct cpufreq_governor cpufreq_scx_gov = {
	.name			= "scx",
	.owner			= THIS_MODULE,
	.flags			= CPUFREQ_GOV_DYNAMIC_SWITCHING,
	.init			= scx_gov_init,
	.exit			= scx_gov_exit,
	.start			= scx_gov_start,
	.stop			= scx_gov_stop,
	.limits			= scx_gov_limits,
};

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_SCX
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return &cpufreq_scx_gov;
}
#endif

struct ctl_table scx_gov_table[] = {
	{
		.procname	= "scx_gov_debug",
		.data		= &sysctl_scx_gov_debug,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

void scx_gov_sysctl_init(void)
{
	struct ctl_table_header *hdr;

	sysctl_scx_gov_debug = 0;
	hdr = register_sysctl("scx_gov", scx_gov_table);
	kmemleak_not_leak(hdr);
}

int hmbird_cpufreq_init(void)
{
	int ret = 0;
	struct scx_sched_cluster *cluster = NULL;
	scx_gov_sysctl_init();

	ret = cpufreq_register_governor(&cpufreq_scx_gov);
	if (ret)
		return ret;

	if (!scx_build_clusters()) {
		ret = -1;
		scx_gov_err("failed to build sched cluster\n");
		goto out;
	}

	for_each_sched_cluster(cluster)
		scx_gov_debug("num_cluster=%d id=%d cpumask=%*pbl capacity=%lu num_cpus=%d\n",
			num_sched_clusters, cluster->id, cpumask_pr_args(&cluster->cpus),
			arch_scale_cpu_capacity(cpumask_first(&cluster->cpus)),
			num_possible_cpus());

	return ret;

out:
	cpufreq_unregister_governor(&cpufreq_scx_gov);
	return ret;
}
