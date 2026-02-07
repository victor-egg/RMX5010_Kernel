// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */
#include <linux/kmemleak.h>
#include <linux/cpufreq.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <../kernel/sched/sched.h>
#include <trace/hooks/sched.h>

#include "./hmbird_gki/scx_main.h"

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
struct scx_sched_cluster *scx_cluster[MAX_CLS_NUM];
struct list_head cluster_head;
#define for_each_sched_cluster(cluster) \
	list_for_each_entry_rcu(cluster, &cluster_head, list)


static struct irq_work scx_cpufreq_irq_work;

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
};

struct scx_gov_cpu {
#ifndef CONFIG_SCX_USE_UTIL_TRACK
	struct waltgov_callback	cb;
#endif
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

static inline void scx_irq_work_queue(struct irq_work *work)
{
	if (likely(cpu_online(raw_smp_processor_id())))
		irq_work_queue(work);
	else
		irq_work_queue_on(work, cpumask_any(cpu_online_mask));
}

void run_scx_irq_work_rollover(void)
{
	scx_irq_work_queue(&scx_cpufreq_irq_work);
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
	cluster_tl = DEFAULT_TARGET_LOAD;
	if (sg_policy->tunables) {
		cluster_tl = sg_policy->tunables->target_loads;
	}

#ifdef CONFIG_SCX_USE_UTIL_TRACK
	window_size_tl = mult_frac(scx_sched_ravg_window, cluster_tl, 100);
#else
	window_size_tl = mult_frac(sched_ravg_window, cluster_tl, 100);
#endif
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

ssize_t set_sugov_tl_scx(unsigned int cpu, char *buf)
{
	struct cpufreq_policy *policy;
	struct scx_gov_policy *sg_policy;
	struct scx_gov_tunables *tunables;
	struct gov_attr_set *attr_set;
	size_t count;

	if (!buf)
		return -EFAULT;

	policy = cpufreq_cpu_get(cpu);
	if (!policy)
		return -ENODEV;

	sg_policy = policy->governor_data;
	if (!sg_policy)
		return -EINVAL;

	tunables = sg_policy->tunables;
	if (!tunables)
		return -ENOMEM;

	attr_set = &tunables->attr_set;
	count = strlen(buf);

	return target_loads_store(attr_set, buf, count);
}
EXPORT_SYMBOL_GPL(set_sugov_tl_scx);

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

static void scx_irq_work(struct irq_work *irq_work)
{
#ifdef CONFIG_SCX_USE_UTIL_TRACK
	cpumask_t lock_cpus;
	struct scx_sched_cluster *cluster;
	struct cpufreq_policy *policy;
	struct scx_sched_rq_stats *srq;
	struct rq *rq;
	int cpu;
	int level = 0;
	u64 wc;
	unsigned long flags;
	struct scx_entity *scx;

	cpumask_copy(&lock_cpus, cpu_possible_mask);

	for_each_cpu(cpu, &lock_cpus) {
		if (level == 0)
			raw_spin_lock(&cpu_rq(cpu)->__lock);
		else
			raw_spin_lock_nested(&cpu_rq(cpu)->__lock, level);
		level++;
	}

	wc = scx_sched_clock();

	for_each_sched_cluster(cluster) {
		cpumask_t cluster_online_cpus;
		u64 prev_runnable_sum = 0;

		if (gov_flag[cluster->id] == 0)
			continue;
		cpumask_and(&cluster_online_cpus, &cluster->cpus, cpu_online_mask);
		for_each_cpu(cpu, &cluster_online_cpus) {
			rq = cpu_rq(cpu);
			scx = get_oplus_ext_entity(rq->curr);
			if (scx)
				scx_update_task_ravg(scx, rq->curr, rq, TASK_UPDATE, wc);
			srq = &per_cpu(scx_sched_rq_stats, cpu);
			if (cpufreq_gov_debug() & DEBUG_FTRACE)
				gov_trace_printk("cpu[%d] prev_runnable_sum[%llu]\n", cpu, srq->prev_runnable_sum);
			prev_runnable_sum = max(prev_runnable_sum, srq->prev_runnable_sum);
		}

		policy = cpufreq_cpu_get_raw(cpumask_first(&cluster_online_cpus));
		if (policy == NULL)
			scx_gov_err("NULL policy [%d]\n", cpumask_first(&cluster_online_cpus));
		scx_gov_update_cpufreq(policy, prev_runnable_sum);
	}

	spin_lock_irqsave(&new_sched_ravg_window_lock, flags);
	if (unlikely(new_scx_sched_ravg_window != scx_sched_ravg_window)) {
		srq = &per_cpu(scx_sched_rq_stats, smp_processor_id());
		if (wc < srq->window_start + new_scx_sched_ravg_window) {
			scx_sched_ravg_window = new_scx_sched_ravg_window;
			scx_fixup_window_dep();
		}
	}
	spin_unlock_irqrestore(&new_sched_ravg_window_lock, flags);

	for_each_cpu(cpu, &lock_cpus) {
		raw_spin_unlock(&cpu_rq(cpu)->__lock);
	}
#endif
}

#ifndef CONFIG_SCX_USE_UTIL_TRACK
void partial_backup_ctrl(void)
{
	int cpu, cluster_id;
	u64 util, cap = 0;
	struct cpufreq_policy *policy;
	struct scx_sched_cluster *cluster;
	int nr_viewed = 0, nr_busy = 0, nr_light = 0, nr_busy_scaled = 0, nr_light_scaled = 0;
	int nr_partial = cpumask_weight(iso_masks.partial);
	struct scx_gov_policy *sg_policy;

	for_each_sched_cluster(cluster) {
		cpumask_t cluster_online_cpus;
		int cpuctrl_high_util, cpuctrl_low_util;
		cpumask_and(&cluster_online_cpus, &cluster->cpus, cpu_online_mask);
		cpu = cpumask_first(&cluster_online_cpus);
		if (cpu >= nr_cpu_ids)
			continue;
		cluster_id = topology_cluster_id(cpu);
		policy = cpufreq_cpu_get_raw(cpu);
		if (!policy) {
			pr_err("partial_backup_ctrl: NULL policy cpu=%d\n", cpu);
			return;
		}
		rcu_read_lock();
		sg_policy = policy->governor_data;
		if (unlikely(!sg_policy) || !gov_flag[cluster_id]) {
			rcu_read_unlock();
			return;
		}
		cap = DIV64_U64_ROUNDUP(sg_policy->freq_cached * arch_scale_cpu_capacity(cpu), policy->cpuinfo.max_freq);
		rcu_read_unlock();
		cpuctrl_high_util = mult_frac(cap, cpuctrl_high_ratio, 100);
		cpuctrl_low_util = mult_frac(cap, cpuctrl_low_ratio, 100);
		for_each_cpu(cpu, &cluster_online_cpus) {
			util = scx_cpu_util(cpu);
			if (scx_cpu_big(cpu) || (partial_enable && scx_cpu_partial(cpu))) {
				if (util > cpuctrl_high_util)
					++nr_busy;
				else if (util < cpuctrl_low_util)
					++nr_light;

				if (util > per_cpu(cpuctrl_high_util_scaled, cpu))
					++nr_busy_scaled;
				else if (util < per_cpu(cpuctrl_low_util_scaled, cpu))
					++nr_light_scaled;
				++nr_viewed;
			}
		}
	}
	if ((nr_busy == nr_viewed) || (nr_busy_scaled == nr_viewed)) {
		if (!nr_partial && !partial_enable)
			partial_enable += 2;
		else
			++partial_enable;
	}
	else if (partial_enable && ((nr_light > nr_partial) || (nr_light_scaled > nr_partial)))
		--partial_enable;

	if (dump_info & SCX_DEBUG_SYSTRACE)
		partial_backup_systrace_c(partial_enable);
}

static void scxgov_update_freq(struct waltgov_callback *cb, u64 time, unsigned int flags)
{
	struct scx_gov_cpu *sg_cpu;
	struct cpufreq_policy *policy;
	u64 exclusive = 0;
	u64 sum = 0, avg = 0, nr = 0, max = 0, prev;
	int cpu, cluster_id;
	if ((flags & WALT_CPUFREQ_ROLLOVER_BIT) && !(flags & WALT_CPUFREQ_CONTINUE_BIT)) {
		sg_cpu = container_of(cb, struct scx_gov_cpu, cb);
		policy = sg_cpu->sg_policy->policy;
		for_each_cpu(cpu, policy->cpus) {
			struct walt_rq *wrq = &per_cpu(walt_rq, cpu);
			if (scx_cpu_partial(cpu) && !partial_enable)
				continue;
			if (scx_cpu_exclusive(cpu)) {
				exclusive = max(exclusive, wrq->prev_runnable_sum + wrq->grp_time.prev_runnable_sum);
				continue;
			}
			prev = wrq->prev_runnable_sum + wrq->grp_time.prev_runnable_sum;
			sum += prev;
			max = max(max, prev);
			nr++;
		}

		if (!exclusive) {
			/* No tasks are running on the exclusive cluster in prev window,
			 * that may be due to the low frequency of other cpus blocking
			 * tasks on the exclusive. Anyway, we select max as freq reference*/
			scx_gov_update_cpufreq(policy, max);
			goto partial_update;
		}
		if (nr)
			avg = div64_u64(sum, nr);
		scx_gov_update_cpufreq(policy, max(exclusive, sysctl_gov_avg_policy ? avg : max));

partial_update:
		cpu = cpumask_first(policy->related_cpus);
		cluster_id = topology_cluster_id(cpu);
		if (cluster_id == num_sched_clusters - 1) {
			partial_backup_ctrl();
		}
	}
}
#endif

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
	BUG_ON(!cluster);

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
#ifndef CONFIG_SCX_USE_UTIL_TRACK
		waltgov_add_callback(cpu, &sg_cpu->cb, scxgov_update_freq);
#endif
	}
	cpu = cpumask_first(policy->related_cpus);
	cluster_id = topology_cluster_id(cpu);
	scx_gov_debug("start cluster[%d] cluster_id[%d] gov\n", cpu, cluster_id);
	if (cluster_id < MAX_CLUSTERS)
		gov_flag[cluster_id] = 1;

	return 0;
}

static void scx_gov_stop(struct cpufreq_policy *policy)
{
	struct scx_gov_policy *sg_policy = policy->governor_data;
	unsigned int cpu, cluster_id;
#ifndef CONFIG_SCX_USE_UTIL_TRACK
	for_each_cpu(cpu, policy->cpus)
		waltgov_remove_callback(cpu);
#endif
	if (!policy->fast_switch_enabled) {
		irq_work_sync(&scx_cpufreq_irq_work);
		kthread_cancel_work_sync(&sg_policy->work);
	}

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
		/*
		 * we have serval resources to update freq
		 * (1) scheduler to run callback
		 * (2) cpufreq_set_policy to call governor->limtis here
		 * so we have serveral times here and we must to keep them same
		 * here we using walt_sched_clock() to keep same with walt scheduler
		 */
		now = ktime_get_ns();

		/*
		 * cpufreq_driver_resolve_freq() has a clamp, so we do not need
		 * to do any sort of additional validation here.
		 */
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

int scx_cpufreq_init(void)
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

	init_irq_work(&scx_cpufreq_irq_work, scx_irq_work);
	return ret;

out:
	cpufreq_unregister_governor(&cpufreq_scx_gov);
	return ret;
}
