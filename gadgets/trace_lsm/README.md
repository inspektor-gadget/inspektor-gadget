# trace lsm

a strace for LSM tracepoints

## Getting started
Pulling the gadget:
```
sudo ig image pull ghcr.io/inspektor-gadget/gadget/trace_lsm:latest
```
Running the gadget:
```
sudo ig run ghcr.io/inspektor-gadget/gadget/trace_lsm:latest [flags]
kubectl gadget run ghcr.io/inspektor-gadget/gadget/trace_lsm:latest [flags]
```

## Flags

### `--trace-all`
trace all LSM tracepoints

Default value: "false"

### `--trace-binder_set_context_mgr`
Trace the binder_set_context_mgr LSM hook

Default value: "false"

### `--trace-binder_transaction`
Trace the binder_transaction LSM hook

Default value: "false"

### `--trace-binder_transfer_binder`
Trace the binder_transfer_binder LSM hook

Default value: "false"

### `--trace-binder_transfer_file`
Trace the binder_transfer_file LSM hook

Default value: "false"

### `--trace-bprm_check_security`
Trace the bprm_check_security LSM hook

Default value: "false"

### `--trace-bprm_committed_creds`
Trace the bprm_committed_creds LSM hook

Default value: "false"

### `--trace-bprm_committing_creds`
Trace the bprm_committing_creds LSM hook

Default value: "false"

### `--trace-bprm_creds_for_exec`
Trace the bprm_creds_for_exec LSM hook

Default value: "false"

### `--trace-bprm_creds_from_file`
Trace the bprm_creds_from_file LSM hook

Default value: "false"

### `--trace-capable`
Trace the capable LSM hook

Default value: "false"

### `--trace-capget`
Trace the capget LSM hook

Default value: "false"

### `--trace-capset`
Trace the capset LSM hook

Default value: "false"

### `--trace-cred_alloc_blank`
Trace the cred_alloc_blank LSM hook

Default value: "false"

### `--trace-cred_free`
Trace the cred_free LSM hook

Default value: "false"

### `--trace-cred_getsecid`
Trace the cred_getsecid LSM hook

Default value: "false"

### `--trace-cred_prepare`
Trace the cred_prepare LSM hook

Default value: "false"

### `--trace-cred_transfer`
Trace the cred_transfer LSM hook

Default value: "false"

### `--trace-d_instantiate`
Trace the d_instantiate LSM hook

Default value: "false"

### `--trace-dentry_create_files_as`
Trace the dentry_create_files_as LSM hook

Default value: "false"

### `--trace-dentry_init_security`
Trace the dentry_init_security LSM hook

Default value: "false"

### `--trace-file_alloc_security`
Trace the file_alloc_security LSM hook

Default value: "false"

### `--trace-file_fcntl`
Trace the file_fcntl LSM hook

Default value: "false"

### `--trace-file_free_security`
Trace the file_free_security LSM hook

Default value: "false"

### `--trace-file_ioctl`
Trace the file_ioctl LSM hook

Default value: "false"

### `--trace-file_lock`
Trace the file_lock LSM hook

Default value: "false"

### `--trace-file_mprotect`
Trace the file_mprotect LSM hook

Default value: "false"

### `--trace-file_open`
Trace the file_open LSM hook

Default value: "false"

### `--trace-file_permission`
Trace the file_permission LSM hook

Default value: "false"

### `--trace-file_receive`
Trace the file_receive LSM hook

Default value: "false"

### `--trace-file_send_sigiotask`
Trace the file_send_sigiotask LSM hook

Default value: "false"

### `--trace-file_set_fowner`
Trace the file_set_fowner LSM hook

Default value: "false"

### `--trace-fs_context_dup`
Trace the fs_context_dup LSM hook

Default value: "false"

### `--trace-fs_context_parse_param`
Trace the fs_context_parse_param LSM hook

Default value: "false"

### `--trace-getprocattr`
Trace the getprocattr LSM hook

Default value: "false"

### `--trace-inode_alloc_security`
Trace the inode_alloc_security LSM hook

Default value: "false"

### `--trace-inode_copy_up`
Trace the inode_copy_up LSM hook

Default value: "false"

### `--trace-inode_copy_up_xattr`
Trace the inode_copy_up_xattr LSM hook

Default value: "false"

### `--trace-inode_create`
Trace the inode_create LSM hook

Default value: "false"

### `--trace-inode_follow_link`
Trace the inode_follow_link LSM hook

Default value: "false"

### `--trace-inode_free_security`
Trace the inode_free_security LSM hook

Default value: "false"

### `--trace-inode_getattr`
Trace the inode_getattr LSM hook

Default value: "false"

### `--trace-inode_getsecctx`
Trace the inode_getsecctx LSM hook

Default value: "false"

### `--trace-inode_getsecid`
Trace the inode_getsecid LSM hook

Default value: "false"

### `--trace-inode_getsecurity`
Trace the inode_getsecurity LSM hook

Default value: "false"

### `--trace-inode_getxattr`
Trace the inode_getxattr LSM hook

Default value: "false"

### `--trace-inode_init_security`
Trace the inode_init_security LSM hook

Default value: "false"

### `--trace-inode_init_security_anon`
Trace the inode_init_security_anon LSM hook

Default value: "false"

### `--trace-inode_invalidate_secctx`
Trace the inode_invalidate_secctx LSM hook

Default value: "false"

### `--trace-inode_killpriv`
Trace the inode_killpriv LSM hook

Default value: "false"

### `--trace-inode_link`
Trace the inode_link LSM hook

Default value: "false"

### `--trace-inode_listsecurity`
Trace the inode_listsecurity LSM hook

Default value: "false"

### `--trace-inode_listxattr`
Trace the inode_listxattr LSM hook

Default value: "false"

### `--trace-inode_mkdir`
Trace the inode_mkdir LSM hook

Default value: "false"

### `--trace-inode_mknod`
Trace the inode_mknod LSM hook

Default value: "false"

### `--trace-inode_need_killpriv`
Trace the inode_need_killpriv LSM hook

Default value: "false"

### `--trace-inode_notifysecctx`
Trace the inode_notifysecctx LSM hook

Default value: "false"

### `--trace-inode_permission`
Trace the inode_permission LSM hook

Default value: "false"

### `--trace-inode_post_setxattr`
Trace the inode_post_setxattr LSM hook

Default value: "false"

### `--trace-inode_readlink`
Trace the inode_readlink LSM hook

Default value: "false"

### `--trace-inode_removexattr`
Trace the inode_removexattr LSM hook

Default value: "false"

### `--trace-inode_rename`
Trace the inode_rename LSM hook

Default value: "false"

### `--trace-inode_rmdir`
Trace the inode_rmdir LSM hook

Default value: "false"

### `--trace-inode_setattr`
Trace the inode_setattr LSM hook

Default value: "false"

### `--trace-inode_setsecctx`
Trace the inode_setsecctx LSM hook

Default value: "false"

### `--trace-inode_setsecurity`
Trace the inode_setsecurity LSM hook

Default value: "false"

### `--trace-inode_setxattr`
Trace the inode_setxattr LSM hook

Default value: "false"

### `--trace-inode_symlink`
Trace the inode_symlink LSM hook

Default value: "false"

### `--trace-inode_unlink`
Trace the inode_unlink LSM hook

Default value: "false"

### `--trace-ipc_getsecid`
Trace the ipc_getsecid LSM hook

Default value: "false"

### `--trace-ipc_permission`
Trace the ipc_permission LSM hook

Default value: "false"

### `--trace-ismaclabel`
Trace the ismaclabel LSM hook

Default value: "false"

### `--trace-kernel_act_as`
Trace the kernel_act_as LSM hook

Default value: "false"

### `--trace-kernel_create_files_as`
Trace the kernel_create_files_as LSM hook

Default value: "false"

### `--trace-kernel_load_data`
Trace the kernel_load_data LSM hook

Default value: "false"

### `--trace-kernel_module_request`
Trace the kernel_module_request LSM hook

Default value: "false"

### `--trace-kernel_post_load_data`
Trace the kernel_post_load_data LSM hook

Default value: "false"

### `--trace-kernel_post_read_file`
Trace the kernel_post_read_file LSM hook

Default value: "false"

### `--trace-kernel_read_file`
Trace the kernel_read_file LSM hook

Default value: "false"

### `--trace-kernfs_init_security`
Trace the kernfs_init_security LSM hook

Default value: "false"

### `--trace-mmap_addr`
Trace the mmap_addr LSM hook

Default value: "false"

### `--trace-mmap_file`
Trace the mmap_file LSM hook

Default value: "false"

### `--trace-move_mount`
Trace the move_mount LSM hook

Default value: "false"

### `--trace-msg_msg_alloc_security`
Trace the msg_msg_alloc_security LSM hook

Default value: "false"

### `--trace-msg_msg_free_security`
Trace the msg_msg_free_security LSM hook

Default value: "false"

### `--trace-msg_queue_alloc_security`
Trace the msg_queue_alloc_security LSM hook

Default value: "false"

### `--trace-msg_queue_associate`
Trace the msg_queue_associate LSM hook

Default value: "false"

### `--trace-msg_queue_free_security`
Trace the msg_queue_free_security LSM hook

Default value: "false"

### `--trace-msg_queue_msgctl`
Trace the msg_queue_msgctl LSM hook

Default value: "false"

### `--trace-msg_queue_msgrcv`
Trace the msg_queue_msgrcv LSM hook

Default value: "false"

### `--trace-msg_queue_msgsnd`
Trace the msg_queue_msgsnd LSM hook

Default value: "false"

### `--trace-netlink_send`
Trace the netlink_send LSM hook

Default value: "false"

### `--trace-path_notify`
Trace the path_notify LSM hook

Default value: "false"

### `--trace-ptrace_access_check`
Trace the ptrace_access_check LSM hook

Default value: "false"

### `--trace-ptrace_traceme`
Trace the ptrace_traceme LSM hook

Default value: "false"

### `--trace-quota_on`
Trace the quota_on LSM hook

Default value: "false"

### `--trace-quotactl`
Trace the quotactl LSM hook

Default value: "false"

### `--trace-release_secctx`
Trace the release_secctx LSM hook

Default value: "false"

### `--trace-sb_alloc_security`
Trace the sb_alloc_security LSM hook

Default value: "false"

### `--trace-sb_clone_mnt_opts`
Trace the sb_clone_mnt_opts LSM hook

Default value: "false"

### `--trace-sb_delete`
Trace the sb_delete LSM hook

Default value: "false"

### `--trace-sb_eat_lsm_opts`
Trace the sb_eat_lsm_opts LSM hook

Default value: "false"

### `--trace-sb_free_mnt_opts`
Trace the sb_free_mnt_opts LSM hook

Default value: "false"

### `--trace-sb_free_security`
Trace the sb_free_security LSM hook

Default value: "false"

### `--trace-sb_kern_mount`
Trace the sb_kern_mount LSM hook

Default value: "false"

### `--trace-sb_mnt_opts_compat`
Trace the sb_mnt_opts_compat LSM hook

Default value: "false"

### `--trace-sb_mount`
Trace the sb_mount LSM hook

Default value: "false"

### `--trace-sb_pivotroot`
Trace the sb_pivotroot LSM hook

Default value: "false"

### `--trace-sb_remount`
Trace the sb_remount LSM hook

Default value: "false"

### `--trace-sb_set_mnt_opts`
Trace the sb_set_mnt_opts LSM hook

Default value: "false"

### `--trace-sb_show_options`
Trace the sb_show_options LSM hook

Default value: "false"

### `--trace-sb_statfs`
Trace the sb_statfs LSM hook

Default value: "false"

### `--trace-sb_umount`
Trace the sb_umount LSM hook

Default value: "false"

### `--trace-secctx_to_secid`
Trace the secctx_to_secid LSM hook

Default value: "false"

### `--trace-secid_to_secctx`
Trace the secid_to_secctx LSM hook

Default value: "false"

### `--trace-sem_alloc_security`
Trace the sem_alloc_security LSM hook

Default value: "false"

### `--trace-sem_associate`
Trace the sem_associate LSM hook

Default value: "false"

### `--trace-sem_free_security`
Trace the sem_free_security LSM hook

Default value: "false"

### `--trace-sem_semctl`
Trace the sem_semctl LSM hook

Default value: "false"

### `--trace-sem_semop`
Trace the sem_semop LSM hook

Default value: "false"

### `--trace-setprocattr`
Trace the setprocattr LSM hook

Default value: "false"

### `--trace-settime`
Trace the settime LSM hook

Default value: "false"

### `--trace-shm_alloc_security`
Trace the shm_alloc_security LSM hook

Default value: "false"

### `--trace-shm_associate`
Trace the shm_associate LSM hook

Default value: "false"

### `--trace-shm_free_security`
Trace the shm_free_security LSM hook

Default value: "false"

### `--trace-shm_shmat`
Trace the shm_shmat LSM hook

Default value: "false"

### `--trace-shm_shmctl`
Trace the shm_shmctl LSM hook

Default value: "false"

### `--trace-syslog`
Trace the syslog LSM hook

Default value: "false"

### `--trace-task_alloc`
Trace the task_alloc LSM hook

Default value: "false"

### `--trace-task_fix_setgid`
Trace the task_fix_setgid LSM hook

Default value: "false"

### `--trace-task_fix_setuid`
Trace the task_fix_setuid LSM hook

Default value: "false"

### `--trace-task_free`
Trace the task_free LSM hook

Default value: "false"

### `--trace-task_getioprio`
Trace the task_getioprio LSM hook

Default value: "false"

### `--trace-task_getpgid`
Trace the task_getpgid LSM hook

Default value: "false"

### `--trace-task_getscheduler`
Trace the task_getscheduler LSM hook

Default value: "false"

### `--trace-task_getsecid_obj`
Trace the task_getsecid_obj LSM hook

Default value: "false"

### `--trace-task_getsid`
Trace the task_getsid LSM hook

Default value: "false"

### `--trace-task_kill`
Trace the task_kill LSM hook

Default value: "false"

### `--trace-task_movememory`
Trace the task_movememory LSM hook

Default value: "false"

### `--trace-task_prctl`
Trace the task_prctl LSM hook

Default value: "false"

### `--trace-task_prlimit`
Trace the task_prlimit LSM hook

Default value: "false"

### `--trace-task_setioprio`
Trace the task_setioprio LSM hook

Default value: "false"

### `--trace-task_setnice`
Trace the task_setnice LSM hook

Default value: "false"

### `--trace-task_setpgid`
Trace the task_setpgid LSM hook

Default value: "false"

### `--trace-task_setrlimit`
Trace the task_setrlimit LSM hook

Default value: "false"

### `--trace-task_setscheduler`
Trace the task_setscheduler LSM hook

Default value: "false"

### `--trace-task_to_inode`
Trace the task_to_inode LSM hook

Default value: "false"

### `--trace-vm_enough_memory`
Trace the vm_enough_memory LSM hook

Default value: "false"
