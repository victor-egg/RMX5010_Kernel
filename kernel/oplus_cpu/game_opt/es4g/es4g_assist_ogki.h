// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */

#ifndef __ES4G_ASSIST_OGKI_H__
#define __ES4G_ASSIST_OGKI_H__

#define LOOKUP_KERNEL_SYMBOL(name) \
static int lookup_##name(void) \
{ \
	int ret; \
	struct kprobe kp_##name = { \
		.symbol_name = #name, \
	}; \
	\
	ret = register_kprobe(&kp_##name); \
	if (ret < 0) { \
		pr_err("lookup " #name " fail!\n"); \
		return -1; \
	} \
	addr_##name = (__typeof__(addr_##name))kp_##name.addr; \
	unregister_kprobe(&kp_##name); \
	return 0; \
}

int es4g_assist_ogki_init(void);
void es4g_assist_ogki_exit(void);

#endif /* __ES4G_ASSIST_OGKI_H__ */
