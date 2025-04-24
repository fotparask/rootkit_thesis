#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>

#include "ftrace_config.h"

MODULE_DESCRIPTION("Module hooking clone() with ftrace");
MODULE_AUTHOR("Fotis <fotparaskevop@gmail.com>");
MODULE_LICENSE("MIT");
MODULE_VERSION("1.0");


#define HOOK(_name, _function, _original)	\
	{					\
		.name = (_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);

static asmlinkage long fh_sys_clone(struct pt_regs *regs)
{
	long ret;

	pr_info("clone() before\n");

	ret = real_sys_clone(regs);

  printk(KERN_INFO "clone() after: %ld\n", ret);

	pr_info("clone() after: %ld\n", ret);

	return ret;
}


static struct ftrace_hook hooks[] = {
  HOOK("__x64_sys_clone",  fh_sys_clone,  &real_sys_clone),
};

static int __init rootkit_init(void)
{
    printk(KERN_INFO "ABOUT TO LOAD THE ROOTKIT\n");
    printk(KERN_INFO "-------------------------------\n");
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
      return err;

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
