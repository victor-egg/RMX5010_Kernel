// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include "hmbird_version.h"
#include "hmbird_ogki/scx_minidump.h"

extern int scx_init(void);
extern void scx_exit(void);


static int __init hmbird_common_init(void)
{
	if (HMBIRD_GKI_VERSION == get_hmbird_version_type()) {
		scx_init();
	} else if (HMBIRD_OGKI_VERSION == get_hmbird_version_type()) {
		hmbird_minidump_init();
		return 0;
	}
	return 0;
}

static void __exit hmbird_common_exit(void)
{
	if (HMBIRD_GKI_VERSION == get_hmbird_version_type()) {
		scx_exit();
	} else if (HMBIRD_OGKI_VERSION == get_hmbird_version_type()) {
		return;
	}
}

module_init(hmbird_common_init);
module_exit(hmbird_common_exit);
MODULE_LICENSE("GPL v2");
