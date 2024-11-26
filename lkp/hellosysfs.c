// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>

static char *hello_string;

static ssize_t hello_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			   size_t count)
{
	kfree(hello_string);
	hello_string = kstrndup(buf, count, GFP_KERNEL);
	return count;
}

static ssize_t hello_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "Hello %s!\n", hello_string);
}

struct kobj_attribute hello_attr = __ATTR_RW(hello);

static int __init hello_init(void)
{
	hello_string = kstrdup("sysfs", GFP_KERNEL);
	return sysfs_create_file(kernel_kobj, &hello_attr.attr);
}
module_init(hello_init)

static void __exit hello_exit(void)
{
	sysfs_remove_file(kernel_kobj, &hello_attr.attr);
	kfree(hello_string);
}
module_exit(hello_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Print \"Hello World\" from sysfs file");
MODULE_LICENSE("GPL");
