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
#if IS_ENABLED(CONFIG_SCHED_WALT)
#include <linux/sched/walt.h>
#endif /* CONFIG_SCHED_WALT */
#include <linux/sched/sched_ext.h>

#include "game_ctrl.h"
#include "es4g/es4g_assist_gki.h"
#include "es4g/es4g_assist_common.h"
#include "hmbird_gki/scx_hooks.h"

#define ES4G_ALLOW_PROC_WR_OPS

#ifndef MAX_NR_CPUS
#define MAX_NR_CPUS (1 << 3)
#endif

static unsigned int es4g_assist_debug = 0;

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

static u32 es4g_select_cpu_mask = 0;

static int select_cpu_list[MAX_NR_CPUS] = {7, 4, 3, 2, 6, 5, -1, -1};

static DEFINE_RWLOCK(critical_task_list_rwlock);
static DEFINE_RWLOCK(select_cpu_list_rwlock);

static inline int prop_to_index(int prop)
{
	return (~prop & 0xf);
}

static inline int index_to_prop(int index)
{
	return (~index & 0xf);
}

static inline int sched_prop_get_task_index(struct task_struct *p __maybe_unused)
{
	return prop_to_index(sched_prop_get_top_thread_id(p));
}

static void remove_slot_of_index(struct key_thread_struct *list, size_t index)
{
	unsigned long dsq_id;
	if (list[index].slot > 0 && likely(list[index].task != NULL)) {
		dsq_id = sched_get_sched_prop(list[index].task) & SCHED_PROP_DEADLINE_MASK;
		sched_set_sched_prop(list[index].task, dsq_id);
		put_task_struct(list[index].task);
	}
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
	WRITE_ONCE(es4g_select_cpu_mask, 0);
	return true;
}

static bool init_key_thread(struct key_thread_struct *list, size_t len)
{
	return clear_key_thread(list, len);
}

static void update_key_thread_cpu(struct key_thread_struct *list, size_t len)
{
	int prio_count[KEY_THREAD_PRIORITY_COUNT + 1] = {0};
	int online_cpumask = (1 << MAX_NR_CPUS) - 1;
	int task_cpumask = online_cpumask;

	/**
	 * clear key task prop if no cpu online
	 */
	if (unlikely(task_cpumask <= 0)) {
		clear_key_thread(list, len);
		return;
	}

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
	for (int i = 0; i < len && task_cpumask > 0; i++) {
		if (list[i].slot <= 0) {
			continue;
		}
		for (int cpu_index = prio_count[list[i].prio]; cpu_index < MAX_NR_CPUS; cpu_index++) {
			if (select_cpu_list[cpu_index] < 0) {
				list[i].cpu = -1;
				break;
			}
			if (1 << select_cpu_list[cpu_index] & task_cpumask) {
				list[i].cpu = select_cpu_list[cpu_index];
				task_cpumask &= ~(1 << select_cpu_list[cpu_index]);
				break;
			}
		}
	}
	read_unlock(&select_cpu_list_rwlock);

	if (heavy_task_index >= 0) {
		list[heavy_task_index].prio++;
	}

	WRITE_ONCE(es4g_select_cpu_mask, online_cpumask & (~task_cpumask));
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
			sched_set_sched_prop(list[first_slot].task,
									SCHED_PROP_DEADLINE_LEVEL3 |
									index_to_prop(first_slot) << SCHED_PROP_TOP_THREAD_SHIFT);
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

static void scx_select_cpu_dfl_hook(void *unused, struct task_struct *p, s32 *cpu)
{
	int index = sched_prop_get_task_index(p);

	if (index >= MAX_KEY_THREAD_RECORD) {
		return;
	}

	if (read_trylock(&critical_task_list_rwlock)) {
		*cpu = critical_thread_list[index].cpu;
		read_unlock(&critical_task_list_rwlock);
	}
}

static void check_preempt_curr_scx_hook(
	void *unused,
	struct rq *rq __maybe_unused,
	struct task_struct *p __maybe_unused,
	int wake_flags __maybe_unused,
	int *check_result)
{
	int index = sched_prop_get_task_index(p);

	if (index >= MAX_KEY_THREAD_RECORD) {
		return;
	}

	if (read_trylock(&critical_task_list_rwlock)) {
		if (critical_thread_list[index].cpu >= 0) {
			*check_result = 1;
		}
		read_unlock(&critical_task_list_rwlock);
	}
}

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

	read_lock(&critical_task_list_rwlock);
	for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
		if (critical_thread_list[i].slot > 0) {
			len += snprintf(page + len, ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD - len,
								"tid=%d, prio=%d, cpu=%d\n",
								critical_thread_list[i].pid, critical_thread_list[i].prio, critical_thread_list[i].cpu);
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
			ret = -EINVAL;
			break;

		case ES4G_COMMON_CTRL_SET_SCHED_PROP:
			ret = -EINVAL;
			break;

		case ES4G_COMMON_CTRL_UNSET_SCHED_PROP:
			ret = -EINVAL;
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
		ret = -EINVAL;
		break;

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
	register_trace_android_vh_scx_select_cpu_dfl(scx_select_cpu_dfl_hook, NULL);
	register_trace_android_vh_check_preempt_curr_scx(check_preempt_curr_scx_hook, NULL);
}

static void unregister_es4g_assist_vendor_hooks(void)
{
	unregister_trace_android_vh_scx_select_cpu_dfl(scx_select_cpu_dfl_hook, NULL);
	unregister_trace_android_vh_check_preempt_curr_scx(check_preempt_curr_scx_hook, NULL);
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
}

static void es4g_remove_proc_entry(void)
{
	if (unlikely(!es4g_dir))
		return;

	remove_proc_entry("es4ga_ctrl", es4g_dir);
	remove_proc_entry("es4ga_debug", es4g_dir);
	remove_proc_entry("critical_task", es4g_dir);
	remove_proc_entry("select_cpu_list", es4g_dir);
	remove_proc_entry("es4g", game_opt_dir);
}

int es4g_assist_gki_init(void)
{
	if (unlikely(!game_opt_dir))
		return -ENOTDIR;

	register_es4g_assist_vendor_hooks();
	es4g_proc_create();

	init_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);

	return 0;
}

void es4g_assist_gki_exit(void)
{
	if (unlikely(!game_opt_dir))
		return;

	unregister_es4g_assist_vendor_hooks();
	es4g_remove_proc_entry();

	clear_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
}
