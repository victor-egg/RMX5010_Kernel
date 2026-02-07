// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */

#include <trace/events/sched.h>
#include <trace/hooks/sched.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/stdarg.h>
#include <linux/kprobes.h>
#if IS_ENABLED(CONFIG_SCHED_WALT)
#include <linux/sched/walt.h>
#endif /* CONFIG_SCHED_WALT */
#if IS_ENABLED(CONFIG_CPU_IDLE_GOV_QCOM_LPM)
#include <drivers/cpuidle/governors/trace-qcom-lpm.h>
#endif /* CONFIG_CPU_IDLE_GOV_QCOM_LPM */

#include <linux/sched/hmbird.h>
#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
#include <linux/sched/hmbird_version.h>
#endif
#endif

#include "game_ctrl.h"
#include "es4g/es4g_assist_ogki.h"
#include "es4g/es4g_assist_common.h"

#define ES4G_ALLOW_PROC_WR_OPS

#ifndef MAX_NR_CPUS
#define MAX_NR_CPUS (1 << 3)
#endif

static unsigned int es4g_assist_debug = 0;

#define DECLARE_DEBUG_TRACE(name, proto, data)				\
	static void __maybe_unused debug_##name(proto) {		\
		if (unlikely(es4g_assist_debug & DEBUG_SYSTRACE)) {	\
			name(data);										\
		}													\
	}
#include "debug_common.h"
#undef DECLARE_DEBUG_TRACE

static struct proc_dir_entry *es4g_dir = NULL;

static struct key_thread_struct {
	pid_t pid;
	struct task_struct *task;
	s32 prio; /* smaller is more critical, range from 0 to 8 */
	u32 slot;
	s32 cpu;
	s32 util;
} critical_thread_list[MAX_KEY_THREAD_RECORD];

static int heavy_task_index = -1;
static int __maybe_unused heavy_task_count = 0;
static int es4g_assist_preempt_policy = 0;

struct isolate_mask {
	u32 strict_isolate;
	u32 pipeline_isolate;
	u32 weak_isolate;
} es4g_isolate_mask = {
	.strict_isolate = 0,
	.pipeline_isolate = 0,
	.weak_isolate = 0,
};

struct cpumask_record
{
	u32 select_cpumask;
	u32 exclusive_cpumask;
	u32 period_disallow_cpumask;
	u32 nonperiod_disallow_cpumask;
	u32 reserved_cpumask;
} es4g_cpumask_record = {
	.select_cpumask = 0,
	.exclusive_cpumask = 0,
	.period_disallow_cpumask = 0,
	.nonperiod_disallow_cpumask = 0,
	.reserved_cpumask = 0,
};

static int select_cpu_list[MAX_NR_CPUS] = {7, 4, 3, 2, 6, 5, -1, -1};
static int sched_prop_to_preempt_prio[ES4G_TASK_PROP_MAX] = {0};

static DEFINE_RWLOCK(critical_task_list_rwlock);
static DEFINE_RWLOCK(select_cpu_list_rwlock);
static DEFINE_RWLOCK(top_task_prop_rwlock);
static DEFINE_RWLOCK(cpumask_record_rwlock);

#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
struct migration_swap_arg {
	struct task_struct *src_task, *dst_task;
	int src_cpu, dst_cpu;
};
#define SWAP_TASK_MAX_NUM 5
#define SWAP_TASK_NUM 2
#define TASK_NAME_MAX_LEN 32
struct task_struct *pipeline_swap_task[SWAP_TASK_NUM];
int pipeline_swap_task_num = 0;
char swap_white_list[SWAP_TASK_NUM][TASK_NAME_MAX_LEN];
bool white_list_valid = false;
#define __NR_NANOSLEEP 101
#define HMBIRD_SCHED_PROP_TMP_AFFINITY	  (1 << 31)
#define PIPELINE_SWAP_MIN					(2)
#define PIPELINE_SWAP_MAX					(20)
struct hrtimer ptimer, btimer;
struct hrtimer migrate_reset_timer;
struct work_struct swap_pipeline_work;
struct irq_work swap_pipeline_irq_work;
static int swap_off, req_boost, pipeline_swap_enable, g_gc_opt, g_hkrpg_opt;
static unsigned long swap_val = 4000000;
static unsigned long reset_swap_val = 25000000;
static int delay_swap_enable = 0;
static struct hmbird_ops *sa_hmbird_ops = NULL;

static u64 pipeline_task_running_time[SWAP_TASK_NUM][2];
static u64 frame_time;

static DEFINE_RWLOCK(pipeline_swap_rwlock);
static DEFINE_RWLOCK(pipeline_swap_white_list_rwlock);
static DEFINE_RAW_SPINLOCK(pipeline_swap_task_lock);

int (*addr_stop_two_cpus)(unsigned int cpu1, unsigned int cpu2, cpu_stop_fn_t fn, void *arg);
bool get_swap_task_from_rt_info_by_white_list(void);
LOOKUP_KERNEL_SYMBOL(stop_two_cpus);

extern int get_critical_task_by_name(const char *name, struct task_struct **task);

void __migrate_swap_task(struct task_struct *p, int cpu)
{
	if (task_on_rq_queued(p)) {
		struct rq *src_rq, *dst_rq;
		src_rq = task_rq(p);
		dst_rq = cpu_rq(cpu);
		deactivate_task(src_rq, p, 0);
		set_task_cpu(p, cpu);
		activate_task(dst_rq, p, 0);
	} else {
		p->wake_cpu = cpu;
	}
}

void hmbird_sched_ops_init(void)
{
	if (HMBIRD_OGKI_VERSION == get_hmbird_version_type()) {
		sa_hmbird_ops = get_hmbird_ops(this_rq());
	}
}
bool is_hmbird_enable(void)
{
	if (sa_hmbird_ops && sa_hmbird_ops->scx_enable
		&& sa_hmbird_ops->scx_enable())
		return true;
	else
		return false;
}

static int migrate_swap_stop(void *data)
{
	struct migration_swap_arg *arg = data;
	struct rq *src_rq, *dst_rq;
	struct hmbird_entity *she, *dhe;
	bool swap_d = true, swap_s = true;

	if (!cpu_active(arg->src_cpu) || !cpu_active(arg->dst_cpu))
		return -EAGAIN;
	src_rq = cpu_rq(arg->src_cpu);
	dst_rq = cpu_rq(arg->dst_cpu);

	guard(double_raw_spinlock)(&arg->src_task->pi_lock, &arg->dst_task->pi_lock);
	guard(double_rq_lock)(src_rq, dst_rq);
	if (task_cpu(arg->dst_task) != arg->dst_cpu) {
		if (task_cpu(arg->dst_task) == arg->src_cpu) {
			swap_d = false;
		} else {
			return -EAGAIN;
		}
	}
	if (task_cpu(arg->src_task) != arg->src_cpu) {
		if (task_cpu(arg->src_task) == arg->dst_cpu) {
			swap_s = false;
		} else {
			return -EAGAIN;
		}
	}
	she = get_hmbird_ts(arg->src_task);
	dhe = get_hmbird_ts(arg->dst_task);
	she->critical_affinity_cpu = arg->dst_cpu;
	dhe->critical_affinity_cpu = arg->src_cpu;
	if (swap_s) {
		__migrate_swap_task(arg->src_task, arg->dst_cpu);
	}

	if (swap_d) {
		__migrate_swap_task(arg->dst_task, arg->src_cpu);
	}
	return 0;
}

static bool get_key_thread_from_rt_info(void)
{
	pipeline_swap_task_num = 0;
	for (int i = 0; i < SWAP_TASK_NUM; i++) {
		if (pipeline_swap_task[i]) {
			put_task_struct(pipeline_swap_task[i]);
			pipeline_swap_task[i] = NULL;
		}
	}
	if (pipeline_swap_enable && white_list_valid && get_swap_task_from_rt_info_by_white_list()) {
		return true;
	}
	return false;
}

static int check_swap_task(struct task_struct *src_task, struct task_struct *dst_task)
{
	struct task_struct *temp = NULL;
	if (!src_task || !dst_task) {
		get_key_thread_from_rt_info();
		return 0;
	}
	if (strncmp(swap_white_list[0], src_task->comm, strlen(swap_white_list[0])) ||
		strncmp(swap_white_list[1], dst_task->comm, strlen(swap_white_list[1]))) {
		if (strncmp(swap_white_list[1], src_task->comm, strlen(swap_white_list[1])) == 0 &&
			strncmp(swap_white_list[0], dst_task->comm, strlen(swap_white_list[0])) == 0) {
			temp = pipeline_swap_task[0];
			WRITE_ONCE(pipeline_swap_task[0], pipeline_swap_task[1]);
			WRITE_ONCE(pipeline_swap_task[1], temp);
			src_task = pipeline_swap_task[0];
			dst_task = pipeline_swap_task[1];
			return 1;
		} else {
			get_key_thread_from_rt_info();
			return 0;
		}
	}
	return 1;
}

int hmbird_pipline_migrate_swap(bool start)
{
	struct migration_swap_arg arg;
	int ret = -EINVAL, src_cpu, dst_cpu, task_avail = 0;
	unsigned long flags;
	raw_spin_lock_irqsave(&pipeline_swap_task_lock, flags);
	struct task_struct *src_task = pipeline_swap_task[0];
	struct task_struct *dst_task = pipeline_swap_task[1];
	task_avail = check_swap_task(src_task, dst_task);
	raw_spin_unlock_irqrestore(&pipeline_swap_task_lock, flags);
	if (!task_avail || !pipeline_swap_enable || !addr_stop_two_cpus || !is_hmbird_enable())
		return ret;

	if (start) {
		src_cpu = select_cpu_list[0];
		dst_cpu = select_cpu_list[1];
	} else {
		src_cpu = select_cpu_list[1];
		dst_cpu = select_cpu_list[0];
	}


	arg = (struct migration_swap_arg) {
		.src_task = src_task,
		.src_cpu = src_cpu,
		.dst_task = dst_task,
		.dst_cpu = dst_cpu,
	};

	if (arg.src_cpu == arg.dst_cpu)
		goto out;
	/*
		* These three tests are all lockless; this is OK since all of them
		* will be re-checked with proper locks held further down the line.
		*/
	if (!cpu_active(arg.src_cpu) || !cpu_active(arg.dst_cpu))
		goto out;
	ret = addr_stop_two_cpus(arg.dst_cpu, arg.src_cpu, migrate_swap_stop, &arg);
out:
	return ret;
}

static void swap_pipeline_work_func(struct work_struct *work)
{
	if (req_boost) {
		hmbird_pipline_migrate_swap(1);
		req_boost = 0;
	} else {
		if (hrtimer_active(&ptimer)) {
			hrtimer_cancel(&ptimer);
		}
		if (cmpxchg(&swap_off, 1, 0)) {
			hmbird_pipline_migrate_swap(0);
		}
	}
}

static bool check_first_swap_status(void)
{
	unsigned long flags;
	bool ret = false;
	u64 end_time;
	raw_spin_lock_irqsave(&pipeline_swap_task_lock, flags);
	end_time = pipeline_task_running_time[0][1];
	if (pipeline_task_running_time[0][1] < pipeline_task_running_time[0][0]) {
		end_time = ktime_get_ns();
	}
	if (frame_time > pipeline_task_running_time[0][0]) {
		pipeline_task_running_time[0][0] = frame_time;
	}
	if (end_time < pipeline_task_running_time[0][0]) {
		ret = false;
	} else if (end_time - pipeline_task_running_time[0][0] > 1000000) {
		ret = true;
	}
	raw_spin_unlock_irqrestore(&pipeline_swap_task_lock, flags);
	return ret;
}

static enum hrtimer_restart notify_pipeline_swap(struct hrtimer *timer)
{
	if (!delay_swap_enable || check_first_swap_status()) {
		queue_work_on(0, system_highpri_wq, &swap_pipeline_work);
		return HRTIMER_NORESTART;
	}
	ktime_t kt = ktime_set(0, 500000);
	hrtimer_forward_now(timer, kt);
	return HRTIMER_RESTART;
}

void notify_pipeline_swap_start(void)
{
	if (!pipeline_swap_enable)
		return;

	if (hrtimer_active(&ptimer))
		hrtimer_cancel(&ptimer);
	frame_time = ktime_get_ns();
	hrtimer_start(&ptimer, ns_to_ktime(swap_val),
				HRTIMER_MODE_REL_PINNED);
	if (hrtimer_active(&migrate_reset_timer)) {
		hrtimer_cancel(&migrate_reset_timer);
	}
	if (reset_swap_val > swap_val) {
		hrtimer_start(&migrate_reset_timer, ns_to_ktime(reset_swap_val), HRTIMER_MODE_REL_PINNED);
	}
	hmbird_pipline_migrate_swap(1);
	swap_off = 1;
}

void scx_boost_or_reset_all(int boost);
static enum hrtimer_restart gc_boost_reset(struct hrtimer *timer)
{
	scx_boost_or_reset_all(0);
	return HRTIMER_NORESTART;
}

static enum hrtimer_restart migrate_reset(struct hrtimer *timer)
{
	req_boost = 1;
	queue_work_on(0, system_highpri_wq, &swap_pipeline_work);
	return HRTIMER_NORESTART;
}

static void swap_pipeline_irq_work_func(struct irq_work *irq_work)
{
	queue_work_on(0, system_highpri_wq, &swap_pipeline_work);
}

static void update_swap_task_running_time(struct task_struct *task, int i, bool is_prev_task)
{
	if (task == pipeline_swap_task[i]) {
		if (!is_prev_task) {
			pipeline_task_running_time[i][0] = ktime_get_ns();
		} else {
			pipeline_task_running_time[i][1] = ktime_get_ns();
		}
	}
}

static void sched_switch_handler(void *unused, bool preempt, struct task_struct *prev,
					struct task_struct *next, unsigned int prev_state)
{
	struct pt_regs *regs;
	struct hmbird_entity *he;
	unsigned long flags;
	int i;
	if (pipeline_swap_enable && is_hmbird_enable() && likely(prev != next)) {
		he = get_hmbird_ts(next);
		if (he->sched_prop & HMBIRD_SCHED_PROP_TMP_AFFINITY) {
			he->critical_affinity_cpu = -1;
			he->sched_prop &= ~HMBIRD_SCHED_PROP_TMP_AFFINITY;
		}
		raw_spin_lock_irqsave(&pipeline_swap_task_lock, flags);
		if (pipeline_swap_task[1]) {
			if (pipeline_swap_enable == 2 && pipeline_swap_task[1] == prev) {
				regs = task_pt_regs(prev);
				if (regs->syscallno == __NR_NANOSLEEP) {
					irq_work_queue(&swap_pipeline_irq_work);
				}
			}

			if (pipeline_swap_task[1]->group_leader->pid == next->group_leader->pid) {
				if (g_gc_opt && !strncmp(next->comm, "GC", 2)) {
					scx_boost_or_reset_all(1);
					if (!hrtimer_active(&btimer))
						hrtimer_start(&btimer, ns_to_ktime(40000000),
								HRTIMER_MODE_REL_PINNED);
					req_boost = 1;
					irq_work_queue(&swap_pipeline_irq_work);
				}
				if (g_hkrpg_opt && !strncmp(next->comm, "Thread-", 7)) {
					hmbird_set_dsq_id(next, SCHED_PROP_DEADLINE_LEVEL4);
				}
			}
		}
		for (i = 0; i < SWAP_TASK_NUM; i++) {
			update_swap_task_running_time(prev, i, true);
			update_swap_task_running_time(next, i, false);
		}
		raw_spin_unlock_irqrestore(&pipeline_swap_task_lock, flags);

		if (g_hkrpg_opt && prev->flags & PF_WQ_WORKER) {
			hmbird_set_dsq_id(prev, SCHED_PROP_DEADLINE_LEVEL4);
			if (prev->nr_cpus_allowed == 1) {
				he = get_hmbird_ts(prev);
				he->critical_affinity_cpu = cpumask_any(prev->cpus_ptr);
			}
		}
	}
}

static void sched_waking_handler(void *unused, struct task_struct *p)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&pipeline_swap_task_lock, flags);
	if (pipeline_swap_enable && is_hmbird_enable()
		&& pipeline_swap_task[0] && pipeline_swap_task[0] == current) {
		if (!strncmp(p->comm, "binder", 6)) {
			struct hmbird_entity *he = get_hmbird_ts(p);
			he->critical_affinity_cpu = task_cpu(current);
			he->sched_prop |= HMBIRD_SCHED_PROP_TMP_AFFINITY;
		}
	}
	raw_spin_unlock_irqrestore(&pipeline_swap_task_lock, flags);
}

static void set_pipeline_swap_proc(int enable, unsigned long val, int gc_opt, int hkrpg_opt, unsigned long reset_val, int delay_enable)
{
	write_lock(&pipeline_swap_rwlock);

	pipeline_swap_enable = enable;
	if (val >= PIPELINE_SWAP_MIN && val <= PIPELINE_SWAP_MAX)
		swap_val = val * 1000000;
	reset_swap_val = reset_val * 1000000;
	g_gc_opt = !!gc_opt;
	g_hkrpg_opt = !!hkrpg_opt;
	delay_swap_enable = delay_enable;

	write_unlock(&pipeline_swap_rwlock);
}

static void set_pipeline_swap(int val, enum es4g_ctrl_pipeline_swap_cmd_id type)
{
	write_lock(&pipeline_swap_rwlock);

	switch (type) {
	case ES4G_SET_PIPELINE_SWAP_ENABLE:
		if (pipeline_swap_enable != val) {
			pipeline_swap_enable = val;
		}
		break;
	case ES4G_SET_PIPELINE_SWAP_VAL:
		if (val >= PIPELINE_SWAP_MIN && val <= PIPELINE_SWAP_MAX &&
				swap_val != val * 1000000) {
			swap_val = val * 1000000;
		}
		break;
	case ES4G_SET_PIPELINE_SWAP_GC:
		if (g_gc_opt != !!val) {
			g_gc_opt = !!val;
		}
		break;
	case ES4G_SET_PIPELINE_SWAP_HKRPG:
		if (g_hkrpg_opt != !!val) {
			g_hkrpg_opt = !!val;
		}
		break;
	case ES4G_SET_PIPELINE_SWAP_RESET_VAL:
		if (reset_swap_val != val * 1000000) {
			reset_swap_val = val * 1000000;
		}
		break;
	case ES4G_SET_PIPELINE_SWAP_DELAY_ENABLE:
		if (delay_swap_enable != !!val) {
			delay_swap_enable = !!val;
		}
		break;
	}

	write_unlock(&pipeline_swap_rwlock);
}

static ssize_t pipeline_swap_proc_write(struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, enable = 0, gc_opt = 0, hkrpg_opt = 0, delay_enable = 0;
	unsigned long val = 10, reset_val = 25;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d %lu %d %d %lu %d", &enable, &val, &gc_opt, &hkrpg_opt, &reset_val, &delay_enable);
	if (ret < 0)
		return -EINVAL;

	set_pipeline_swap_proc(enable, val, gc_opt, hkrpg_opt, reset_val, delay_enable);
	return count;
}

static ssize_t pipeline_swap_proc_read(struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
	char page[128] = {0};
	int len;
	read_lock(&pipeline_swap_rwlock);
	len = sprintf(page, "enble=%d, val=%lu, gc_opt=%d, hkrpg_opt=%d, reset_val=%lu, delay_enable=%d\n",
				pipeline_swap_enable, swap_val, g_gc_opt, g_hkrpg_opt, reset_swap_val, delay_swap_enable);
	read_unlock(&pipeline_swap_rwlock);
	if (len >= sizeof(page)) {
		len = sizeof(page) - 1;
		page[len] = '\0';
	}
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops pipeline_swap_proc_ops = {
	.proc_write		= pipeline_swap_proc_write,
	.proc_read		= pipeline_swap_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t pipeline_swap_white_list_proc_write(struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
	char page[128] = {0};
	char *token, *line;
	int ret;
	int white_list_count = 0;

	if (count >= sizeof(page)) {
		pr_warn("Input exceeds max buffer size %zu\n", sizeof(page));
		return -EINVAL;
	}

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;
	page[sizeof(page)-1] = '\0';

	write_lock(&pipeline_swap_white_list_rwlock);
	line = page;
	while ((token = strsep(&line, ";")) && token != NULL && white_list_count < SWAP_TASK_NUM) {
		if (strlen(token) >= TASK_NAME_MAX_LEN) {
			pr_warn("Name[%d] exceeds max length %d\n",
				   white_list_count, TASK_NAME_MAX_LEN - 1);
			white_list_valid = false;
			goto unlock;
		}

		strncpy(swap_white_list[white_list_count], token, TASK_NAME_MAX_LEN-1);
		swap_white_list[white_list_count][TASK_NAME_MAX_LEN-1] = '\0';
		white_list_count++;
	}
	if (white_list_count != SWAP_TASK_NUM) {
		white_list_valid = false;
	} else {
		white_list_valid = true;
	}
unlock:
	write_unlock(&pipeline_swap_white_list_rwlock);

	return count;
}

static ssize_t pipeline_swap_white_list_proc_read(struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
	char page[64] = {0};
	int len = 0, ret, i;
	size_t remaining = sizeof(page);
	read_lock(&pipeline_swap_white_list_rwlock);
	for (i = 0; white_list_valid && i < SWAP_TASK_NUM && remaining > 1; ++i) {
		ret = snprintf(page + len, remaining, "%s\n", swap_white_list[i]);
		if (ret >= remaining) {
			break;
		}
		len += ret;
		remaining -= ret;
	}
	read_unlock(&pipeline_swap_white_list_rwlock);
	if (len >= sizeof(page)) {
		pr_warn("White list output truncated\n");
		len = sizeof(page) - 1;
		page[len] = '\0';
	}

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops pipeline_swap_white_list_proc_ops = {
	.proc_write		= pipeline_swap_white_list_proc_write,
	.proc_read		= pipeline_swap_white_list_proc_read,
	.proc_lseek		= default_llseek,
};

static void hmbird_swap_pipeline_init(void)
{
	int ret = lookup_stop_two_cpus();
	if (ret < 0) {
		pr_err("lookup_stop_two_cpus fail\n");
		return;
	}
	hmbird_sched_ops_init();
	hrtimer_init(&ptimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	ptimer.function = notify_pipeline_swap;
	hrtimer_init(&btimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	btimer.function = gc_boost_reset;
	hrtimer_init(&migrate_reset_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	migrate_reset_timer.function = migrate_reset;
	INIT_WORK(&swap_pipeline_work, swap_pipeline_work_func);
	init_irq_work(&swap_pipeline_irq_work, swap_pipeline_irq_work_func);
	register_trace_sched_switch(sched_switch_handler, NULL);
	register_trace_sched_waking(sched_waking_handler, NULL);
}
#endif
#endif

static inline bool task_specific_type(uint32_t prop, enum es4g_task_prop_type type)
{
	return test_bit(type << TOP_TASK_SHIFT, (unsigned long *)&prop);
}

static inline void set_top_task_prop_locked(struct task_struct *p, u64 set, u64 clear)
{
	write_lock(&top_task_prop_rwlock);
	set_top_task_prop(p, set, clear);
	write_unlock(&top_task_prop_rwlock);
}

static inline void set_task_specific_type(struct task_struct *p, enum es4g_task_prop_type type)
{
	set_top_task_prop(p, 1 << (type + TOP_TASK_SHIFT), 0);
}

static inline void unset_task_specific_type(struct task_struct *p, enum es4g_task_prop_type type)
{
	set_top_task_prop(p, 0, 1 << (type + TOP_TASK_SHIFT));
}

static inline void init_sched_prop_to_preempt_prio(void)
{
	/**
	 * prio list: 8 > 7 > 1 > other > 0 > 2
	 *
	 * type 8: 5
	 * type 7: 4
	 * type 1,9: 3
	 * other: 2
	 * type 0: 1
	 * type 2: 0
	 *
	 */
	for (int i = 0; i < ES4G_TASK_PROP_MAX; i++) {
		switch (i) {
		case ES4G_TASK_PROP_TRANSIENT_AND_CRITICAL:
			sched_prop_to_preempt_prio[i] = 5;
			break;

		case ES4G_TASK_PROP_PERIODIC_AND_CRITICAL:
			sched_prop_to_preempt_prio[i] = 4;
			break;

		case ES4G_TASK_PROP_PIPELINE:
		case ES4G_TASK_PROP_ISOLATE:
			sched_prop_to_preempt_prio[i] = 3;
			break;

		case ES4G_TASK_PROP_COMMON:
			sched_prop_to_preempt_prio[i] = 1;
			break;

		case ES4G_TASK_PROP_DEBUG_OR_LOG:
			sched_prop_to_preempt_prio[i] = 0;
			break;

		default:
			sched_prop_to_preempt_prio[i] = 2;
			break;
		}
	}
}

static inline enum es4g_task_prop_type es4g_get_task_type(struct task_struct *p)
{
	uint32_t prop = get_top_task_prop(p);

	if (task_specific_type(prop, ES4G_TASK_PROP_TRANSIENT_AND_CRITICAL)) {
		return ES4G_TASK_PROP_TRANSIENT_AND_CRITICAL;
	}
	if (task_specific_type(prop, ES4G_TASK_PROP_PERIODIC_AND_CRITICAL)) {
		return ES4G_TASK_PROP_PERIODIC_AND_CRITICAL;
	}
	if (task_specific_type(prop, ES4G_TASK_PROP_PIPELINE)) {
		return ES4G_TASK_PROP_PIPELINE;
	}
	if (task_specific_type(prop, ES4G_TASK_PROP_COMMON) ||
			!task_specific_type(prop, ES4G_TASK_PROP_DEBUG_OR_LOG)) {
		return ES4G_TASK_PROP_COMMON;
	}
	return ES4G_TASK_PROP_DEBUG_OR_LOG;
}

static inline bool __maybe_unused es4g_prio_higher(struct task_struct *a, struct task_struct *b)
{
	int type_a = es4g_get_task_type(a);
	int type_b = es4g_get_task_type(b);

	return sched_prop_to_preempt_prio[type_a] > sched_prop_to_preempt_prio[type_b];
}

static void update_real_isolate_cpumask(void)
{
	int cpu;
	struct rq *rq;
	struct hmbird_rq *hrq;
	struct rq_flags rf;
	int strict_isolate = READ_ONCE(es4g_isolate_mask.strict_isolate);
	int pipeline_isolate = READ_ONCE(es4g_cpumask_record.select_cpumask) & READ_ONCE(es4g_isolate_mask.pipeline_isolate);
	int weak_isolate = READ_ONCE(es4g_isolate_mask.weak_isolate);

	es4g_cpumask_record.exclusive_cpumask = strict_isolate | pipeline_isolate;
	es4g_cpumask_record.period_disallow_cpumask = strict_isolate | pipeline_isolate | weak_isolate;
	es4g_cpumask_record.nonperiod_disallow_cpumask = strict_isolate | pipeline_isolate;

	for_each_possible_cpu(cpu) {
		rq = cpu_rq(cpu);
		rq_lock_irqsave(rq, &rf);

		hrq = get_hmbird_rq(rq);
		if (likely(hrq)) {
			hrq->pipeline = test_bit(cpu, (unsigned long *)&es4g_cpumask_record.select_cpumask);
			hrq->exclusive = test_bit(cpu, (unsigned long *)&es4g_cpumask_record.exclusive_cpumask);
			hrq->period_disallow = test_bit(cpu, (unsigned long *)&es4g_cpumask_record.period_disallow_cpumask);
			hrq->nonperiod_disallow = test_bit(cpu, (unsigned long *)&es4g_cpumask_record.nonperiod_disallow_cpumask);
		}

		rq_unlock_irqrestore(rq, &rf);
	}
}

static void remove_slot_of_index(struct key_thread_struct *list, size_t index)
{
	struct hmbird_entity *he;

	rcu_read_lock();
	if (list[index].slot > 0 && likely(list[index].task)) {
		set_top_task_prop_locked(list[index].task, 0, TOP_TASK_BITS_MASK);
		he = get_hmbird_ts(list[index].task);
		if (likely(he)) {
			he->critical_affinity_cpu = -1;
		}
		put_task_struct(list[index].task);
	}
	rcu_read_unlock();
	list[index].pid = -1;
	list[index].task = NULL;
	list[index].prio = -1;
	list[index].slot = 0;
	list[index].cpu = -1;
	list[index].util = -1;
	if (heavy_task_index == index) {
		heavy_task_index = -1;
	}
}

static bool clear_key_thread(struct key_thread_struct *list, size_t len)
{
	write_lock(&critical_task_list_rwlock);
	for (int i = 0; i < len; i++) {
		remove_slot_of_index(list, i);
	}
	write_unlock(&critical_task_list_rwlock);
	write_lock(&cpumask_record_rwlock);
	WRITE_ONCE(es4g_cpumask_record.select_cpumask, 0);
	update_real_isolate_cpumask();
	write_unlock(&cpumask_record_rwlock);
	return true;
}

static bool init_key_thread(struct key_thread_struct *list, size_t len)
{
	return clear_key_thread(list, len);
}

#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
bool get_swap_task_from_rt_info_by_white_list(void)
{
	int i;
	if (!white_list_valid) {
		return false;
	}
	read_lock(&pipeline_swap_white_list_rwlock);
	for (i = 0; i < SWAP_TASK_NUM; i++) {
		get_critical_task_by_name(swap_white_list[i], &pipeline_swap_task[i]);
		if (pipeline_swap_task[i] == NULL) {
			memset(pipeline_swap_task, 0, sizeof(pipeline_swap_task));
			pipeline_swap_task_num = 0;
			read_unlock(&pipeline_swap_white_list_rwlock);
			return false;
		}
		++pipeline_swap_task_num;
	}
	read_unlock(&pipeline_swap_white_list_rwlock);
	return true;
}
#endif
#endif

static void update_key_thread_cpu(struct key_thread_struct *list, size_t len)
{
	int prio_count[KEY_THREAD_PRIORITY_COUNT + 1] = {0};
	int select_cpu_mask = 0;
	u32 pipeline_isolate_mask = READ_ONCE(es4g_isolate_mask.pipeline_isolate);
	struct hmbird_entity *he;
#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
	bool get_white_list_status = false;
#endif
#endif

	/* boost priority of heavy task */
	if (heavy_task_index >= 0) {
		list[heavy_task_index].prio--;
	}

	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0) {
			prio_count[list[i].prio + 1]++;
		}
	}
	/* 1st and the last slot is not necessary to count */
	for (int i = 2; i < KEY_THREAD_PRIORITY_COUNT; i++) {
		prio_count[i] += prio_count[i - 1];
	}

	read_lock(&select_cpu_list_rwlock);
	write_lock(&top_task_prop_rwlock);
#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
	unsigned long flags;
	raw_spin_lock_irqsave(&pipeline_swap_task_lock, flags);
	get_white_list_status = get_key_thread_from_rt_info();
	raw_spin_unlock_irqrestore(&pipeline_swap_task_lock, flags);
#endif
#endif
	for (int i = 0; i < len; i++) {
		if (list[i].slot <= 0 || prio_count[list[i].prio] >= MAX_NR_CPUS) {
			continue;
		}
		list[i].cpu = select_cpu_list[prio_count[list[i].prio]];
		he = get_hmbird_ts(list[i].task);
		if (likely(he)) {
			he->critical_affinity_cpu = select_cpu_list[prio_count[list[i].prio]];
		}
#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
		if (pipeline_swap_enable && !get_white_list_status) {
			if (he->critical_affinity_cpu >= 0) {
				if (prio_count[list[i].prio] == 0) {
					unsigned long flags;
					raw_spin_lock_irqsave(&pipeline_swap_task_lock, flags);
					pipeline_swap_task[0] = list[i].task;
					++pipeline_swap_task_num;
					rcu_read_lock();
					if (pipeline_swap_task[0]) {
						get_task_struct(pipeline_swap_task[0]);
					}
					rcu_read_unlock();
					raw_spin_unlock_irqrestore(&pipeline_swap_task_lock, flags);
				}
				else if (prio_count[list[i].prio] == 1) {
					unsigned long flags;
					raw_spin_lock_irqsave(&pipeline_swap_task_lock, flags);
					pipeline_swap_task[1] = list[i].task;
					++pipeline_swap_task_num;
					rcu_read_lock();
					if (pipeline_swap_task[1]) {
						get_task_struct(pipeline_swap_task[1]);
					}
					rcu_read_unlock();
					raw_spin_unlock_irqrestore(&pipeline_swap_task_lock, flags);
				}
			}
		}
#endif
#endif
		if (list[i].cpu < 0) {
			unset_task_specific_type(list[i].task, ES4G_TASK_PROP_PIPELINE);
			unset_task_specific_type(list[i].task, ES4G_TASK_PROP_ISOLATE);
		} else {
			set_task_specific_type(list[i].task, ES4G_TASK_PROP_PIPELINE);
			if (pipeline_isolate_mask & (1 << list[i].cpu)) {
				set_task_specific_type(list[i].task, ES4G_TASK_PROP_ISOLATE);
			}
			select_cpu_mask |= 1 << list[i].cpu;
		}
		prio_count[list[i].prio]++;
	}
	write_unlock(&top_task_prop_rwlock);
	read_unlock(&select_cpu_list_rwlock);

	if (heavy_task_index >= 0) {
		list[heavy_task_index].prio++;
	}

	write_lock(&cpumask_record_rwlock);
	WRITE_ONCE(es4g_cpumask_record.select_cpumask, select_cpu_mask);
	update_real_isolate_cpumask();
	write_unlock(&cpumask_record_rwlock);
}

static bool add_key_thread(struct key_thread_struct *list, size_t len, pid_t pid, s32 prio)
{
	int first_slot = -1;
	bool update = false;

	if (prio > MIN_KEY_THREAD_PRIORITY) {
		prio = MIN_KEY_THREAD_PRIORITY;
	}
	if (prio < MAX_KEY_THREAD_PRIORITY_US) {
		prio = MAX_KEY_THREAD_PRIORITY_US;
	}

	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0) {
			if (list[i].pid == pid) {
				if (list[i].prio != prio) {
					list[i].prio = prio;
					update = true;
				}
				goto out;
			}
		} else {
			if (first_slot < 0) {
				first_slot = i;
			}
		}
	}
	if (first_slot >= 0) {
		rcu_read_lock();
		list[first_slot].task = find_task_by_vpid(pid);
		if (list[first_slot].task) {
			get_task_struct(list[first_slot].task);
			list[first_slot].pid = pid;
			list[first_slot].prio = prio;
			list[first_slot].slot = 1;
			list[first_slot].util = -1;
			hmbird_set_sched_prop(list[first_slot].task, SCHED_PROP_DEADLINE_LEVEL3);
			set_top_task_prop_locked(list[first_slot].task, 1, 0);
			update = true;
		}
		rcu_read_unlock();
	}

out:
	if (update) {
		heavy_task_index = -1;
	}

	return update;
}

static bool remove_key_thread(struct key_thread_struct *list, size_t len, pid_t pid)
{
	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0 && list[i].pid == pid) {
			remove_slot_of_index(list, i);
			return true;
		}
	}
	return false;
}

#if IS_ENABLED(CONFIG_CPU_IDLE_GOV_QCOM_LPM)
static void scx_sched_lpm_disallowed_time_hook(void *unused, int cpu, int *timeout_allowed)
{
	struct rq *rq = cpu_rq(cpu);
	struct hmbird_rq *hrq = get_hmbird_rq(rq);
	if (likely(hrq)) {
		*timeout_allowed = !!(hrq->pipeline);
	}
}
#endif /* CONFIG_CPU_IDLE_GOV_QCOM_LPM */

static int es4g_assist_proc_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int es4g_assist_proc_release(struct inode *inode, struct file *file)
{
	return 0;
}

static void set_es4g_assist_debug(int debug)
{
	es4g_assist_debug = debug < 0 ? 0 : debug;
}

static void set_es4g_assist_preempt_policy(int type)
{
	es4g_assist_preempt_policy = type < 0 ? 0 : type;
}

static void set_es4g_assist_top_task_prop(pid_t pid, int prop)
{
	struct task_struct *task = NULL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task) {
		set_top_task_prop_locked(task, prop << TOP_TASK_SHIFT, 0);
	}
	rcu_read_unlock();
}

static void unset_es4g_assist_top_task_prop(pid_t pid, int prop)
{
	struct task_struct *task = NULL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task) {
		set_top_task_prop_locked(task, 0, prop << TOP_TASK_SHIFT);
	}
	rcu_read_unlock();
}

static ssize_t es4g_assist_debug_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret, debug;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%d", &debug);
	if (ret < 1) {
		return -EINVAL;
	}

	set_es4g_assist_debug(debug);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_assist_debug_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int len;

	len = snprintf(page, ONE_PAGE_SIZE - 1, "%d\n", es4g_assist_debug);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_assist_debug_proc_ops = {
	.proc_write		= es4g_assist_debug_proc_write,
	.proc_read		= es4g_assist_debug_proc_read,
	.proc_lseek		= default_llseek,
};

static bool __maybe_unused set_critical_task(int tid, int prio)
{
	bool ret;

	if (tid < 0 && prio < 0) {
		return clear_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
	}

	if (tid < 0)
		return false;

	write_lock(&critical_task_list_rwlock);
	if (prio < 0) {
		ret = remove_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD, tid);
	} else {
		ret = add_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD, tid, prio);
	}
	if (ret) {
		update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
	}
	write_unlock(&critical_task_list_rwlock);

	return ret;
}

static bool batch_set_critical_task(struct es4g_ctrl_info *data, struct key_thread_struct *list, size_t len)
{
	int pair;
	int tid;
	int prio;
	bool update;

	if (data->size <= 0 || (data->size & 1)) {
		return false;
	}

	if (data->data[0] < 0 && data->data[1] < 0) {
		return clear_key_thread(list, len);
	}

	pair = data->size / 2;
	update = false;

	write_lock(&critical_task_list_rwlock);
	for (int i = 0; i < pair; i++) {
		tid = data->data[i * 2];
		prio = data->data[i * 2 + 1];
		if (prio >= 0) {
			continue;
		}
		if (remove_key_thread(list, len, tid)) {
			update = true;
		}
	}
	for (int i = 0; i < pair; i++) {
		tid = data->data[i * 2];
		prio = data->data[i * 2 + 1];
		if (prio < 0) {
			continue;
		}
		if (add_key_thread(list, len, tid, prio)) {
			update = true;
		}
	}
	if (update) {
		update_key_thread_cpu(list, len);
	}
	write_unlock(&critical_task_list_rwlock);

	return update;
}

static ssize_t es4g_critical_task_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret;
	int tid, prio;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d %d", &tid, &prio);
	if (ret != 2)
		return -EINVAL;

	if (!set_critical_task(tid, prio)) {
		return -EINVAL;
	}

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_critical_task_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD] = {0};
	int len = 0;
	struct hmbird_entity *he;
	int cpu;

	read_lock(&critical_task_list_rwlock);
	for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
		if (critical_thread_list[i].slot > 0 && critical_thread_list[i].task) {
			he = get_hmbird_ts(critical_thread_list[i].task);
			cpu = he->critical_affinity_cpu;
			len += snprintf(page + len, ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD - len,
								"tid=%d, prio=%d, cpu=%d\n",
								critical_thread_list[i].pid, critical_thread_list[i].prio, cpu);
		}
	}
	if (heavy_task_index >= 0) {
		len += snprintf(page + len, ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD - len,
								"heavy task is %d\n", critical_thread_list[heavy_task_index].pid);
	}
	read_unlock(&critical_task_list_rwlock);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_critical_task_proc_ops = {
	.proc_write		= es4g_critical_task_proc_write,
	.proc_read		= es4g_critical_task_proc_read,
	.proc_lseek		= default_llseek,
};

static void update_select_cpu_list(s64 *data, size_t len)
{
	if (len > MAX_NR_CPUS) {
		len = MAX_NR_CPUS;
	}

	write_lock(&select_cpu_list_rwlock);
	for (int i = 0; i < len; i++) {
		select_cpu_list[i] = data[i];
	}
	for (int i = len; i < MAX_NR_CPUS; i++) {
		select_cpu_list[i] = -1;
	}
	write_unlock(&select_cpu_list_rwlock);

	write_lock(&critical_task_list_rwlock);
	update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
	write_unlock(&critical_task_list_rwlock);
}

static ssize_t es4g_select_cpu_list_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret;
	s64 cpu_list[MAX_KEY_THREAD_RECORD] = {0};

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%lld %lld %lld %lld %lld %lld %lld %lld",
					&cpu_list[0],
					&cpu_list[1],
					&cpu_list[2],
					&cpu_list[3],
					&cpu_list[4],
					&cpu_list[5],
					&cpu_list[6],
					&cpu_list[7]);
	if (ret <= 0) {
		return -EINVAL;
	}

	update_select_cpu_list(cpu_list, ret);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_select_cpu_list_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE << 1] = {0};
	int len = 0;

	read_lock(&select_cpu_list_rwlock);
	for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
		if (select_cpu_list[i] >= 0) {
			len += snprintf(page + len, (ONE_PAGE_SIZE << 1) - len, "%d: %d\n", i, select_cpu_list[i]);
		} else {
			break;
		}
	}
	read_unlock(&select_cpu_list_rwlock);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_select_cpu_list_proc_ops = {
	.proc_write		= es4g_select_cpu_list_proc_write,
	.proc_read		= es4g_select_cpu_list_proc_read,
	.proc_lseek		= default_llseek,
};

static void set_isolate_cpus(int isolate_cpus, enum es4g_isolate_type type)
{
	switch (type) {
	case ES4G_ISOLATE_STRICT:
		if (isolate_cpus == READ_ONCE(es4g_isolate_mask.strict_isolate)) {
			return;
		}
		WRITE_ONCE(es4g_isolate_mask.strict_isolate, isolate_cpus);
		break;

	case ES4G_ISOLATE_PIPELINE:
		if (isolate_cpus == READ_ONCE(es4g_isolate_mask.pipeline_isolate)) {
			return;
		}
		WRITE_ONCE(es4g_isolate_mask.pipeline_isolate, isolate_cpus);
		break;

	case ES4G_ISOLATE_WEAK:
		if (isolate_cpus == READ_ONCE(es4g_isolate_mask.weak_isolate)) {
			return;
		}
		WRITE_ONCE(es4g_isolate_mask.weak_isolate, isolate_cpus);
		break;

	default:
		break;
	}

	if (type == ES4G_ISOLATE_PIPELINE) {
		write_lock(&critical_task_list_rwlock);
		update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
		write_unlock(&critical_task_list_rwlock);
	} else {
		write_lock(&cpumask_record_rwlock);
		update_real_isolate_cpumask();
		write_unlock(&cpumask_record_rwlock);
	}

	debug_trace_pr_val_uint(type, isolate_cpus);
}

static ssize_t es4g_isolate_cpus_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int strict_isolate, pipeline_isolate, weak_isolate;
	int ret;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%d:%d:%d", &pipeline_isolate, &weak_isolate, &strict_isolate);
	if (ret != 3) {
		return -EINVAL;
	}

	set_isolate_cpus(pipeline_isolate, ES4G_ISOLATE_PIPELINE);
	set_isolate_cpus(weak_isolate, ES4G_ISOLATE_WEAK);
	set_isolate_cpus(strict_isolate, ES4G_ISOLATE_STRICT);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_isolate_cpus_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int len = 0;
	int pipeline_isolate = READ_ONCE(es4g_isolate_mask.pipeline_isolate);
	int weak_isolate = READ_ONCE(es4g_isolate_mask.weak_isolate);
	int strict_isolate = READ_ONCE(es4g_isolate_mask.strict_isolate);

	len = snprintf(page, ONE_PAGE_SIZE - 1, "%d:%d:%d\n", pipeline_isolate, weak_isolate, strict_isolate);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_isolate_cpus_proc_ops = {
	.proc_write		= es4g_isolate_cpus_proc_write,
	.proc_read		= es4g_isolate_cpus_proc_read,
	.proc_lseek		= default_llseek,
};

static long es4g_assist_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct es4g_ctrl_info data;
	void __user *uarg = (void __user *)arg;
	long ret = 0;

	if ((_IOC_TYPE(cmd) != ES4G_MAGIC) || (_IOC_NR(cmd) >= ES4G_MAX_ID)) {
		return -EINVAL;
	}

	if (copy_from_user(&data, uarg, sizeof(data))) {
		return -EFAULT;
	}

	switch (cmd) {
	case CMD_ID_ES4G_COMMON_CTRL:
		switch (data.data[0]) {
		case ES4G_COMMON_CTRL_DEBUG_LEVEL:
			set_es4g_assist_debug(data.data[1]);
			break;

		case ES4G_COMMON_CTRL_PREEMPT_TYPE:
			set_es4g_assist_preempt_policy(data.data[1]);
			break;

		case ES4G_COMMON_CTRL_SET_SCHED_PROP:
			set_es4g_assist_top_task_prop(data.data[1], data.data[2]);
			break;

		case ES4G_COMMON_CTRL_UNSET_SCHED_PROP:
			unset_es4g_assist_top_task_prop(data.data[1], data.data[2]);
			break;

		default:
			break;
		}
		break;

	case CMD_ID_ES4G_SET_CRITICAL_TASK:
		batch_set_critical_task(&data, critical_thread_list, MAX_KEY_THREAD_RECORD);
		break;

	case CMD_ID_ES4G_SELECT_CPU_LIST:
		update_select_cpu_list(data.data, data.size);
		break;

	case CMD_ID_ES4G_SET_ISOLATE_CPUS:
		if (data.size > 0) {
			set_isolate_cpus(data.data[0], ES4G_ISOLATE_PIPELINE);
		}
		if (data.size > 1) {
			set_isolate_cpus(data.data[1], ES4G_ISOLATE_WEAK);
		}
		if (data.size > 2) {
			set_isolate_cpus(data.data[2], ES4G_ISOLATE_STRICT);
		}
		break;

#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
	case CMD_ID_ES4G_SET_PIPELINE_SWAP:
		if (data.size > 0) {
			set_pipeline_swap(data.data[0], ES4G_SET_PIPELINE_SWAP_ENABLE);
		}
		if (data.size > 1) {
			set_pipeline_swap(data.data[1], ES4G_SET_PIPELINE_SWAP_VAL);
		}
		if (data.size > 2) {
			set_pipeline_swap(data.data[2], ES4G_SET_PIPELINE_SWAP_GC);
		}
		if (data.size > 3) {
			set_pipeline_swap(data.data[3], ES4G_SET_PIPELINE_SWAP_HKRPG);
		}
		if (data.size > 4) {
			set_pipeline_swap(data.data[4], ES4G_SET_PIPELINE_SWAP_RESET_VAL);
		}
		if (data.size > 5) {
			set_pipeline_swap(data.data[5], ES4G_SET_PIPELINE_SWAP_DELAY_ENABLE);
		}
		break;
#endif
#endif

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

#if IS_ENABLED(CONFIG_COMPAT)
static long compat_es4g_assist_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return es4g_assist_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif /* CONFIG_COMPAT */

static const struct proc_ops es4g_assist_sys_ctrl_proc_ops = {
	.proc_ioctl			= es4g_assist_ioctl,
	.proc_open			= es4g_assist_proc_open,
	.proc_release		= es4g_assist_proc_release,
#if IS_ENABLED(CONFIG_COMPAT)
	.proc_compat_ioctl	= compat_es4g_assist_ioctl,
#endif /* CONFIG_COMPAT */
	.proc_lseek			= default_llseek,
};

static void register_es4g_assist_vendor_hooks(void)
{
#if IS_ENABLED(CONFIG_CPU_IDLE_GOV_QCOM_LPM)
	register_trace_android_vh_scx_sched_lpm_disallowed_time(scx_sched_lpm_disallowed_time_hook, NULL);
#endif /* CONFIG_CPU_IDLE_GOV_QCOM_LPM */
}

static void unregister_es4g_assist_vendor_hooks(void)
{
#if IS_ENABLED(CONFIG_CPU_IDLE_GOV_QCOM_LPM)
	unregister_trace_android_vh_scx_sched_lpm_disallowed_time(scx_sched_lpm_disallowed_time_hook, NULL);
#endif /* CONFIG_CPU_IDLE_GOV_QCOM_LPM */
}

static void es4g_proc_create(void)
{
	es4g_dir = proc_mkdir("es4g", game_opt_dir);

	if (unlikely(!es4g_dir))
		return;

	proc_create_data("es4ga_ctrl", 0644, es4g_dir, &es4g_assist_sys_ctrl_proc_ops, NULL);
	proc_create_data("es4ga_debug", 0644, es4g_dir, &es4g_assist_debug_proc_ops, NULL);
	proc_create_data("critical_task", 0644, es4g_dir, &es4g_critical_task_proc_ops, NULL);
	proc_create_data("select_cpu_list", 0644, es4g_dir, &es4g_select_cpu_list_proc_ops, NULL);
	proc_create_data("isolate_cpus", 0644, es4g_dir, &es4g_isolate_cpus_proc_ops, NULL);
#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
	proc_create_data("pipeline_swap", 0664, es4g_dir, &pipeline_swap_proc_ops, NULL);
	proc_create_data("pipeline_swap_white_list", 0664, es4g_dir, &pipeline_swap_white_list_proc_ops, NULL);
#endif
#endif
}

static void es4g_remove_proc_entry(void)
{
	if (unlikely(!es4g_dir))
		return;

	remove_proc_entry("es4ga_ctrl", es4g_dir);
	remove_proc_entry("es4ga_debug", es4g_dir);
	remove_proc_entry("critical_task", es4g_dir);
	remove_proc_entry("select_cpu_list", es4g_dir);
	remove_proc_entry("isolate_cpus", es4g_dir);
	remove_proc_entry("es4g", game_opt_dir);
#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
	remove_proc_entry("pipeline_swap", es4g_dir);
	remove_proc_entry("pipeline_swap_white_list", es4g_dir);
#endif
#endif
}

int es4g_assist_ogki_init(void)
{
	if (unlikely(!game_opt_dir))
		return -ENOTDIR;

#ifdef CONFIG_HMBIRD_SCHED
#if IS_ENABLED(CONFIG_SCHED_WALT)
	hmbird_swap_pipeline_init();
#endif
#endif

	register_es4g_assist_vendor_hooks();
	es4g_proc_create();

	init_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
	init_sched_prop_to_preempt_prio();

	return 0;
}

void es4g_assist_ogki_exit(void)
{
	if (unlikely(!game_opt_dir))
		return;

	unregister_es4g_assist_vendor_hooks();
	es4g_remove_proc_entry();

	clear_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
}
