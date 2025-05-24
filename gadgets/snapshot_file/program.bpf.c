// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2025 Your Name
 *
 * Snapshot File Gadget
 *
 * Iterates over all open files of each task and emits one record per file.
 */

 #include <vmlinux.h>
 #include <bpf/bpf_helpers.h>
 
 #include <gadget/macros.h>
 #include <gadget/filter.h>
 #include <gadget/types.h>

 /*  
  * User-configurable filters:  
  *   - file_type_mask: bitmask selecting which file types to include  
  *   - show_threads:    whether to snapshot per-thread (tid) rather than per-process (tgid)  
  */
 const volatile u32 file_type_mask = 0xFFFFFFFF;
 const volatile bool show_threads  = false;

 #define MAX_PATH_LEN 256

struct gadget_file {
    __u32  mntns_id;                 
    char   comm[TASK_COMM_LEN];      
    __u32  pid, tid;                 
    __u32  fd;                     
    __u32  type;                  
    char   path[MAX_PATH_LEN];       
	__u64  inode;
	__u32  flags; 
	__u32  mode;
};

enum file_type {
    FILE_TYPE_REGULAR = 1,
    FILE_TYPE_SOCKET,
    FILE_TYPE_PIPE,
    FILE_TYPE_BPF_MAP,
	FILE_TYPE_DIRECTORY,
	FILE_TYPE_CHAR_DEV,
	FILE_TYPE_BLOCK_DEV,
	FILE_TYPE_SYMLINK,
	FILE_TYPE_OTHER
    /* … */
};

#define S_IFMT   00170000  /* bitmask for the file type bitfields */
#define S_IFSOCK 0140000   /* socket */
#define S_IFLNK  0120000   /* symbolic link */
#define S_IFREG  0100000   /* regular file */
#define S_IFBLK  0060000   /* block device */
#define S_IFDIR  0040000   /* directory */
#define S_IFCHR  0020000   /* character device */
#define S_IFIFO  0010000   /* FIFO */


  
 GADGET_PARAM(file_type_mask);
 GADGET_PARAM(show_threads);
 
 GADGET_SNAPSHOTTER(files, gadget_file, ig_snap_file);
 
 static __always_inline
 u32 classify_file_type(struct file *file)
 {
	 u32 mode = BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT;
 
	 switch (mode) {
	 case S_IFREG:
		 return FILE_TYPE_REGULAR;
	 case S_IFDIR:
		 return FILE_TYPE_DIRECTORY;
	 case S_IFIFO:
		 return FILE_TYPE_PIPE;
	 case S_IFSOCK:
		 return FILE_TYPE_SOCKET;
	 case S_IFCHR:
		 return FILE_TYPE_CHAR_DEV;
	 case S_IFBLK:
		 return FILE_TYPE_BLOCK_DEV;
	 case S_IFLNK:
		 return FILE_TYPE_SYMLINK;
	 default:
		 return FILE_TYPE_OTHER;
	 }
 }

 static __always_inline int copy_dentry_name(struct path *path, char *buf, int buf_len)
{
	// barebones implementation to get the first part of the dentry name
    struct dentry *dentry;
    const unsigned char *name;
    u32 name_len;

    if (!path || !buf)
        return -1;

    dentry = BPF_CORE_READ(path, dentry);
    name = BPF_CORE_READ(dentry, d_name.name);
    name_len = BPF_CORE_READ(dentry, d_name.len);

    if (name_len >= buf_len)
        name_len = buf_len - 1;

    if (bpf_probe_read_kernel_str(buf, name_len + 1, name) < 0)
        return -1;

    return 0;
}

 /*  
  * BPF iterator program: one invocation per (task, file)  
  */
 SEC("iter/task_file")
int ig_snap_file(struct bpf_iter__task_file *ctx)
{
    struct seq_file   *seq  = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    struct file       *file = ctx->file;
    struct gadget_file  info;

    if (!task || !file)
        return 0;
                   sizeof(info.type));

    info.mntns_id = task->nsproxy->mnt_ns->ns.inum;
    __builtin_memcpy(info.comm, task->comm, TASK_COMM_LEN);
    info.pid      = task->tgid;
    info.tid      = task->pid;
    info.fd       = ctx->fd;       
	info.inode = BPF_CORE_READ(file, f_inode, i_ino);
	info.flags = BPF_CORE_READ(file, f_flags);
	info.mode  = BPF_CORE_READ(file, f_mode);
   
   info.type = classify_file_type(file);
   
   if (!((1U << info.type) & file_type_mask))
   return 0;  // skip this file
 
   copy_dentry_name(&file->f_path, info.path, MAX_PATH_LEN);
    bpf_seq_write(seq, &info, sizeof(info));
    return 0;
}

 
 char _license[] SEC("license") = "GPL";
 