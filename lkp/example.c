// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>

static int __init example_init(void)
{
	return 0;
}
module_init(example_init)

static void __exit example_exit(void)
{
}
module_exit(example_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Example module");
MODULE_LICENSE("GPL");
