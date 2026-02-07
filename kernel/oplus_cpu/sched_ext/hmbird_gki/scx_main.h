/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */
#ifndef _SCX_SE_H_
#define _SCX_SE_H_

#include <linux/sched.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/cgroup-defs.h>
#include <linux/sched/cputime.h>
#include <../kernel/sched/sched.h>
#include <../../../kernel/sched/walt/walt.h>
#include <../kernel/oplus_cpu/sched/sched_assist/sa_common.h>
#include "sched_ext.h"

#define MAX_BPF_DSQS (10)
#define MIN_CGROUP_DL_IDX (5)      /* 8ms */
#define DEFAULT_CGROUP_DL_IDX (8)  /* 64ms */
#define NON_PERIOD_START	(5)
#define NON_PERIOD_END		(MAX_BPF_DSQS)
#define DSQ_BITMASK		((1U << MAX_BPF_DSQS) - 1)
#define PERIOD_BITMASK	((1U << NON_PERIOD_START) - 1)
#define NON_PERIOD_BITMASK	(DSQ_BITMASK & (~PERIOD_BITMASK))
extern u32 SCX_BPF_DSQS_DEADLINE[MAX_BPF_DSQS];
#define NUMS_CGROUP_KNIDS		(256)
extern u8 cgroup_ids_tab[NUMS_CGROUP_KNIDS];
/*sysctl*/
extern unsigned int dump_info;

#define SCX_DEBUG_FTRACE		(1 << 0)
#define SCX_DEBUG_SYSTRACE		(1 << 1)
#define SCX_DEBUG_PRINTK		(1 << 2)
#define SCX_DEBUG_PANIC			(1 << 3)

#define scx_trace_printk(fmt, ...)	\
do {										\
		trace_printk("scx_sched_ext :"fmt, ##__VA_ARGS__);	\
} while (0)

#define debug_trace_printk(fmt, ...)	\
do {										\
	if (dump_info & SCX_DEBUG_FTRACE)			\
		trace_printk("scx_sched_ext :"fmt, ##__VA_ARGS__);	\
} while (0)

#define debug_printk(fmt, ...)	\
{							\
	if (dump_info & SCX_DEBUG_PRINTK)	\
		printk_deferred("scx_sched_ext[%s]: "fmt, __func__, ##__VA_ARGS__); \
}

#define scx_assert_rq_lock(rq)	\
do {			\
	if (unlikely(!raw_spin_is_locked(&rq->__lock))) { \
		printk_deferred("on CPU%d: %s task %s(%d) unlocked access for cpu=%d stack[%pS <== %pS <== %pS]\n", \
			raw_smp_processor_id(), __func__, current->comm, current->pid, rq->cpu,             \
			(void *)CALLER_ADDR0, (void *)CALLER_ADDR1, (void *)CALLER_ADDR2);          \
		BUG_ON(-1);					\
	}	\
} while (0)

#define scx_assert_spin_held(lock)	\
do {			\
	if (unlikely(!raw_spin_is_locked(lock))) { \
		printk_deferred("on CPU%d: %s task %s(%d) unlocked access for lock=%s stack[%pS <== %pS <== %pS]\n", \
			raw_smp_processor_id(), __func__, current->comm, current->pid, #lock,             \
			(void *)CALLER_ADDR0, (void *)CALLER_ADDR1, (void *)CALLER_ADDR2);          \
		BUG_ON(-1);					\
	}	\
} while (0)

#define SCX_BUG(fmt, ...)		\
do {										\
	printk_deferred("scx_sched_ext[%s]:"fmt, __func__, ##__VA_ARGS__);	\
	if (dump_info & SCX_DEBUG_PANIC)			\
		BUG_ON(-1);								\
} while (0)

#define SCHED_PRINT(arg)	printk_deferred("%s=%llu", #arg, (unsigned long long)arg)
void scx_task_dump(struct task_struct *p);

#define REGISTER_TRACE(vendor_hook, handler, data, err)	\
do {								\
	ret = register_trace_##vendor_hook(handler, data);				\
	if (ret) {						\
		pr_err("scx_sched_ext:failed to register_trace_"#vendor_hook", ret=%d\n", ret);	\
		goto err;					\
	}							\
} while (0)

#define UNREGISTER_TRACE(vendor_hook, handler, data)	\
do {								\
	unregister_trace_##vendor_hook(handler, data);				\
} while (0)

#define DIV64_U64_ROUNDUP(X, Y) div64_u64((X) + (Y - 1), Y)

#ifdef CONFIG_FAIR_GROUP_SCHED
/* Walk up scheduling entities hierarchy */
#define for_each_sched_entity(se) \
		for (; se; se = se->parent)
#else
#define for_each_sched_entity(se) \
		for (; se; se = NULL)
#endif

enum scene {
	DEFAULT = 0,
	SGAME = 1,
	USER_SET = 2,
	SCENE_MAX
};
extern unsigned int scene_in;

struct scene_cfg {
	char	iso_little[10];
	char	iso_big[10];
	char	iso_partial[10];
	char	iso_exclusive[10];
	int	frame_per_sec;
	bool 	shadow_tick_enable;
	bool 	idle_ctl;
	bool	exclusive_sync_ctl;
};

struct scx_dsq_stats {
	u64	cumulative_runnable_avg_scaled;
	int	nr_period_tasks;
	int	nr_tasks;
};

struct scx_sched_rq_stats {
	u64			window_start;
	u64			latest_clock;
	u32			prev_window_size;
	u64			task_exec_scale;
	u64			prev_runnable_sum;
	u64			curr_runnable_sum;
	int			iso_idx;
	struct scx_dsq_stats	local_dsq_s;
};

/*
 * Dispatch queue (dsq) is a simple FIFO which is used to buffer between the
 * scheduler core and the BPF scheduler. See the documentation for more details.
 */
struct scx_dispatch_q {
	raw_spinlock_t		lock;
	struct list_head	fifo;	/* processed in dispatching order */
	struct rb_root_cached	priq;	/* processed in p->scx.dsq_vtime order */
	u32			nr;
	u64			id;
	u32			idx;
	int			cpu;
	struct rhash_head	hash_node;
	struct llist_node	free_node;
	struct rcu_head		rcu;
	u64                     last_consume_at;
	bool                    is_timeout;
};


/* scx_entity.flags */
enum scx_ent_flags {
	SCX_TASK_QUEUED		= 1 << 0, /* on ext runqueue */
	SCX_TASK_BAL_KEEP	= 1 << 1, /* balance decided to keep current */
	SCX_TASK_ENQ_LOCAL	= 1 << 2, /* used by scx_select_cpu_dfl() to set SCX_ENQ_LOCAL */

	SCX_TASK_OPS_PREPPED	= 1 << 8, /* prepared for BPF scheduler enable */
	SCX_TASK_OPS_ENABLED	= 1 << 9, /* task has BPF scheduler enabled */

	SCX_TASK_WATCHDOG_RESET = 1 << 16, /* task watchdog counter should be reset */
	SCX_TASK_DEQD_FOR_SLEEP	= 1 << 17, /* last dequeue was for SLEEP */

	SCX_TASK_CURSOR		= 1 << 31, /* iteration cursor, not a task */
};

/* scx_entity.dsq_flags */
enum scx_ent_dsq_flags {
	SCX_TASK_DSQ_ON_PRIQ	= 1 << 0, /* task is queued on the priority queue of a dsq */
};

enum scx_enq_flags {
	/* expose select ENQUEUE_* flags as enums */
	SCX_ENQ_WAKEUP		= ENQUEUE_WAKEUP,
	SCX_ENQ_HEAD		= ENQUEUE_HEAD,

	/* high 32bits are SCX specific */

	/*
	 * Set the following to trigger preemption when calling
	 * scx_bpf_dispatch() with a local dsq as the target. The slice of the
	 * current task is cleared to zero and the CPU is kicked into the
	 * scheduling path. Implies %SCX_ENQ_HEAD.
	 */
	SCX_ENQ_PREEMPT		= 1LLU << 32,

	/*
	 * The task being enqueued was previously enqueued on the current CPU's
	 * %SCX_DSQ_LOCAL, but was removed from it in a call to the
	 * bpf_scx_reenqueue_local() kfunc. If bpf_scx_reenqueue_local() was
	 * invoked in a ->cpu_release() callback, and the task is again
	 * dispatched back to %SCX_LOCAL_DSQ by this current ->enqueue(), the
	 * task will not be scheduled on the CPU until at least the next invocation
	 * of the ->cpu_acquire() callback.
	 */
	SCX_ENQ_REENQ		= 1LLU << 40,

	/*
	 * The task being enqueued is the only task available for the cpu. By
	 * default, ext core keeps executing such tasks but when
	 * %SCX_OPS_ENQ_LAST is specified, they're ops.enqueue()'d with
	 * %SCX_ENQ_LAST and %SCX_ENQ_LOCAL flags set.
	 *
	 * If the BPF scheduler wants to continue executing the task,
	 * ops.enqueue() should dispatch the task to %SCX_DSQ_LOCAL immediately.
	 * If the task gets queued on a different dsq or the BPF side, the BPF
	 * scheduler is responsible for triggering a follow-up scheduling event.
	 * Otherwise, Execution may stall.
	 */
	SCX_ENQ_LAST		= 1LLU << 41,

	/*
	 * A hint indicating that it's advisable to enqueue the task on the
	 * local dsq of the currently selected CPU. Currently used by
	 * select_cpu_dfl() and together with %SCX_ENQ_LAST.
	 */
	SCX_ENQ_LOCAL		= 1LLU << 42,

	/* high 8 bits are internal */
	__SCX_ENQ_INTERNAL_MASK	= 0xffLLU << 56,

	SCX_ENQ_CLEAR_OPSS	= 1LLU << 56,
	SCX_ENQ_DSQ_PRIQ	= 1LLU << 57,
};

enum scx_deq_flags {
	/* expose select DEQUEUE_* flags as enums */
	SCX_DEQ_SLEEP		= DEQUEUE_SLEEP,

	/* high 32bits are SCX specific */

	/*
	 * The generic core-sched layer decided to execute the task even though
	 * it hasn't been dispatched yet. Dequeue from the BPF side.
	 */
	SCX_DEQ_CORE_SCHED_EXEC	= 1LLU << 32,
};

#define NUM_ISO_CLUSTERS	4
struct scx_iso_masks {
	union {
		struct {
			cpumask_var_t	little;
			cpumask_var_t	big;
			cpumask_var_t	partial;
			cpumask_var_t	exclusive;
		};
		cpumask_var_t	cluster[NUM_ISO_CLUSTERS];
	};
};

#define MAX_YIELD_SLEEP		(2000ULL)
#define MIN_YIELD_SLEEP		(200ULL)
#define	DEFAULT_YIELD_SLEEP_TH	(10)

struct sched_yield_state {
	raw_spinlock_t	lock;
	unsigned long	cnt;
	unsigned long	usleep;
	int usleep_times;
};

DECLARE_PER_CPU(struct scx_dispatch_q[MAX_BPF_DSQS], gdsqs);
DECLARE_PER_CPU(unsigned long, dsqs_map);
DECLARE_PER_CPU(struct sched_yield_state, ystate);
extern struct scx_iso_masks iso_masks;
DECLARE_PER_CPU(struct scx_sched_rq_stats, scx_sched_rq_stats);
static inline cpumask_t *scx_cpu_iso_cluster(int cpu)
{
	struct scx_sched_rq_stats *srq = &per_cpu(scx_sched_rq_stats, cpu);
	if (srq->iso_idx < 0 || srq->iso_idx >= NUM_ISO_CLUSTERS)
		return NULL;

	return iso_masks.cluster[srq->iso_idx];
}

int parse_and_set_cpus(const char *input, struct cpumask *mask);
void update_scx_cfg_scene(struct scene_cfg *cfg);
extern struct scene_cfg scx_cfg[SCENE_MAX];

static inline bool scx_cpu_partial(int cpu)
{
	return cpumask_test_cpu(cpu, iso_masks.partial);
}

static inline bool scx_cpu_exclusive(int cpu)
{
	return cpumask_test_cpu(cpu, iso_masks.exclusive);
}

static inline bool scx_cpu_little(int cpu)
{
	return cpumask_test_cpu(cpu, iso_masks.little);
}

static inline bool scx_cpu_big(int cpu)
{
	return cpumask_test_cpu(cpu, iso_masks.big);
}

static inline struct scx_entity *get_oplus_ext_entity(struct task_struct *p)
{
	struct oplus_task_struct *ots = get_oplus_task_struct(p);
	if (!ots) {
		WARN_ONCE(1, "scx_sched_ext:get_oplus_ext_entity NULL!");
		return NULL;
	}
	return &ots->scx;
}

extern atomic_t scx_enter_count;
extern unsigned int scx_stats_trace;
extern void scx_reinit_queue_work(void);
#define SCX_ENABLE_PENDING			(-1)

static inline bool scx_enabled_enter(void)
{
	bool ret = scx_stats_trace;
	if (ret) {
		atomic_inc(&scx_enter_count);
		if (unlikely(!scx_stats_trace)) {
			atomic_dec(&scx_enter_count);
			return !ret;
		}
	}
	return ret;
}

static inline void scx_enabled_exit(void)
{
	atomic_dec(&scx_enter_count);
}

extern bool scx_clock_suspended;
extern u64 scx_clock_last;
static inline u64 scx_sched_clock(void)
{
	if (unlikely(scx_clock_suspended))
		return scx_clock_last;
	return sched_clock();
}

static inline u64 scx_rq_clock(struct rq *rq)
{
	struct scx_sched_rq_stats *srq = &per_cpu(scx_sched_rq_stats, cpu_of(rq));

	if (unlikely(scx_clock_suspended))
		return scx_clock_last;

	scx_assert_rq_lock(rq);

	if (!(rq->clock_update_flags & RQCF_UPDATED))
		update_rq_clock(rq);

	return max(rq_clock(rq), srq->latest_clock);
}

extern noinline int tracing_mark_write(const char *buf);

extern u16 balance_small_task_th;
#ifdef CONFIG_SCX_USE_UTIL_TRACK
/*scx_util_trace*/
extern int scx_sched_ravg_window;
extern int new_scx_sched_ravg_window;
extern spinlock_t new_sched_ravg_window_lock;
extern unsigned int scx_scale_demand_divisor;
extern u64 tick_sched_clock;
extern atomic64_t scx_run_rollover_lastq_ws;
extern u32 balance_small_task_th_runtime;
extern u16 scx_init_load_windows_scaled;
extern u32 scx_init_load_windows;

/*util = runtime * 1024 / window_size */
static inline u64 scx_scale_time_to_util(u64 d)
{
	do_div(d, scx_scale_demand_divisor);
	return d;
}

static inline u32 scx_scale_util_to_time(u16 util)
{
	return util * scx_scale_demand_divisor;
}

/*called while scx_sched_ravg_window changed or init*/
static inline void scx_fixup_window_dep(void)
{
	scx_scale_demand_divisor = scx_sched_ravg_window >> SCHED_CAPACITY_SHIFT;
	balance_small_task_th_runtime = scx_scale_util_to_time(balance_small_task_th);
	scx_init_load_windows_scaled = balance_small_task_th + 1;
	scx_init_load_windows = balance_small_task_th_runtime + 1;
}

u16 scx_cpu_util(int cpu);
static inline unsigned long scx_cpu_load(int cpu)
{
	struct scx_sched_rq_stats *srq = &per_cpu(scx_sched_rq_stats, cpu);
	struct scx_entity *curr_scx = NULL;
	u64 curr_load;
	if (cpu_rq(cpu)->curr) {
		curr_scx = get_oplus_ext_entity(cpu_rq(cpu)->curr);
	}

	curr_load = curr_scx ? curr_scx->sts.demand_scaled : 0;

	return srq->local_dsq_s.cumulative_runnable_avg_scaled + curr_load;
}
#else
static inline u16 scx_cpu_util(int cpu)
{
	u64 prev_runnable_sum;
	struct walt_rq *wrq = &per_cpu(walt_rq, cpu);

	prev_runnable_sum = wrq->prev_runnable_sum + wrq->grp_time.prev_runnable_sum;
	do_div(prev_runnable_sum, wrq->prev_window_size >> SCHED_CAPACITY_SHIFT);

	return (u16)prev_runnable_sum;
}

void scx_window_rollover_run_once(struct rq *rq);
#endif

static inline int nr_period_tasks(int cpu)
{
	struct scx_sched_rq_stats *srq = &per_cpu(scx_sched_rq_stats, cpu);
	struct scx_entity *curr_scx = NULL;

	if (cpu_rq(cpu)->curr) {
		curr_scx = get_oplus_ext_entity(cpu_rq(cpu)->curr);
	}

	return (curr_scx && (curr_scx->gdsq_idx < NON_PERIOD_START)) ?
				(srq->local_dsq_s.nr_period_tasks + 1) : srq->local_dsq_s.nr_period_tasks;
}

#ifdef CONFIG_SCX_USE_UTIL_TRACK
/*util_track*/
void scx_update_task_ravg(struct scx_entity *scx, struct task_struct *p, struct rq *rq, int event, u64 wallclock);
void sched_ravg_window_change(int frame_per_sec);
void scx_trace_dispatch_enqueue(struct scx_entity *scx, struct task_struct *p, struct rq *rq);
void scx_trace_dispatch_dequeue(struct scx_entity *scx, struct task_struct *p, struct rq *rq);
#else
static inline void scx_update_task_ravg(struct scx_entity *scx, struct task_struct *p, struct rq *rq, int event, u64 wallclock) {}
#endif
/*scx_sched_gki*/
extern int partial_enable;
extern unsigned int scx_idle_ctl;
extern unsigned int scx_tick_ctl;
extern unsigned int scx_newidle_balance_ctl;
extern unsigned int scx_exclusive_sync_ctl;
extern unsigned int sysctl_yield_opt_enable;
extern unsigned int sysctl_gov_avg_policy;
extern int cpuctrl_high_ratio;
extern int cpuctrl_low_ratio;
extern int cpuctrl_high_ratio_scaled;
extern int cpuctrl_low_ratio_scaled;
DECLARE_PER_CPU(int, cpuctrl_high_util_scaled);
DECLARE_PER_CPU(int, cpuctrl_low_util_scaled);

void partial_backup_ctrl(void);
int scx_sched_gki_init_early(void);
void scx_sched_gki_init(void);
void scx_tick_entry(struct rq *rq);
void scx_scheduler_tick(void);
void partial_load_ctrl(struct rq *rq);
int find_idx_from_task(struct task_struct *p);
void scx_smp_call_newidle_balance(int cpu);
void partial_backup_systrace_c(int partial_enable);

/*cpufreq_gov*/
int scx_cpufreq_init(void);
void run_scx_irq_work_rollover(void);
void scx_gov_update_cpufreq(struct cpufreq_policy *policy, u64 prev_runnable_sum);

/*shadow_tick*/
extern unsigned int sysctl_shadow_tick_enable;
int scx_shadow_tick_init(void);
void start_shadow_tick_timer(void);

#endif /* _SCX_SE_H_ */
