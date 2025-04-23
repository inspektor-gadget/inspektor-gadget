# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
events[("events")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
trace_lsm_binder_set_context_mgr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_binder_set_context_mgr["trace_lsm_binder_set_context_mgr"]
trace_lsm_binder_transaction -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_binder_transaction["trace_lsm_binder_transaction"]
trace_lsm_binder_transfer_binder -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_binder_transfer_binder["trace_lsm_binder_transfer_binder"]
trace_lsm_binder_transfer_file -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_binder_transfer_file["trace_lsm_binder_transfer_file"]
trace_lsm_bprm_check_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_bprm_check_security["trace_lsm_bprm_check_security"]
trace_lsm_bprm_committed_creds -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_bprm_committed_creds["trace_lsm_bprm_committed_creds"]
trace_lsm_bprm_committing_creds -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_bprm_committing_creds["trace_lsm_bprm_committing_creds"]
trace_lsm_bprm_creds_for_exec -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_bprm_creds_for_exec["trace_lsm_bprm_creds_for_exec"]
trace_lsm_bprm_creds_from_file -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_bprm_creds_from_file["trace_lsm_bprm_creds_from_file"]
trace_lsm_capable -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_capable["trace_lsm_capable"]
trace_lsm_capget -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_capget["trace_lsm_capget"]
trace_lsm_capset -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_capset["trace_lsm_capset"]
trace_lsm_cred_alloc_blank -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_cred_alloc_blank["trace_lsm_cred_alloc_blank"]
trace_lsm_cred_free -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_cred_free["trace_lsm_cred_free"]
trace_lsm_cred_getsecid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_cred_getsecid["trace_lsm_cred_getsecid"]
trace_lsm_cred_prepare -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_cred_prepare["trace_lsm_cred_prepare"]
trace_lsm_cred_transfer -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_cred_transfer["trace_lsm_cred_transfer"]
trace_lsm_d_instantiate -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_d_instantiate["trace_lsm_d_instantiate"]
trace_lsm_dentry_create_files_as -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_dentry_create_files_as["trace_lsm_dentry_create_files_as"]
trace_lsm_dentry_init_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_dentry_init_security["trace_lsm_dentry_init_security"]
trace_lsm_file_alloc_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_alloc_security["trace_lsm_file_alloc_security"]
trace_lsm_file_fcntl -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_fcntl["trace_lsm_file_fcntl"]
trace_lsm_file_free_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_free_security["trace_lsm_file_free_security"]
trace_lsm_file_ioctl -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_ioctl["trace_lsm_file_ioctl"]
trace_lsm_file_lock -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_lock["trace_lsm_file_lock"]
trace_lsm_file_mprotect -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_mprotect["trace_lsm_file_mprotect"]
trace_lsm_file_open -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_open["trace_lsm_file_open"]
trace_lsm_file_permission -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_permission["trace_lsm_file_permission"]
trace_lsm_file_receive -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_receive["trace_lsm_file_receive"]
trace_lsm_file_send_sigiotask -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_send_sigiotask["trace_lsm_file_send_sigiotask"]
trace_lsm_file_set_fowner -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_file_set_fowner["trace_lsm_file_set_fowner"]
trace_lsm_fs_context_dup -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_fs_context_dup["trace_lsm_fs_context_dup"]
trace_lsm_fs_context_parse_param -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_fs_context_parse_param["trace_lsm_fs_context_parse_param"]
trace_lsm_getprocattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_getprocattr["trace_lsm_getprocattr"]
trace_lsm_inode_alloc_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_alloc_security["trace_lsm_inode_alloc_security"]
trace_lsm_inode_copy_up -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_copy_up["trace_lsm_inode_copy_up"]
trace_lsm_inode_copy_up_xattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_copy_up_xattr["trace_lsm_inode_copy_up_xattr"]
trace_lsm_inode_create -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_create["trace_lsm_inode_create"]
trace_lsm_inode_follow_link -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_follow_link["trace_lsm_inode_follow_link"]
trace_lsm_inode_free_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_free_security["trace_lsm_inode_free_security"]
trace_lsm_inode_getattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_getattr["trace_lsm_inode_getattr"]
trace_lsm_inode_getsecctx -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_getsecctx["trace_lsm_inode_getsecctx"]
trace_lsm_inode_getsecid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_getsecid["trace_lsm_inode_getsecid"]
trace_lsm_inode_getsecurity -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_getsecurity["trace_lsm_inode_getsecurity"]
trace_lsm_inode_getxattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_getxattr["trace_lsm_inode_getxattr"]
trace_lsm_inode_init_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_init_security["trace_lsm_inode_init_security"]
trace_lsm_inode_init_security_anon -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_init_security_anon["trace_lsm_inode_init_security_anon"]
trace_lsm_inode_invalidate_secctx -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_invalidate_secctx["trace_lsm_inode_invalidate_secctx"]
trace_lsm_inode_killpriv -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_killpriv["trace_lsm_inode_killpriv"]
trace_lsm_inode_link -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_link["trace_lsm_inode_link"]
trace_lsm_inode_listsecurity -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_listsecurity["trace_lsm_inode_listsecurity"]
trace_lsm_inode_listxattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_listxattr["trace_lsm_inode_listxattr"]
trace_lsm_inode_mkdir -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_mkdir["trace_lsm_inode_mkdir"]
trace_lsm_inode_mknod -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_mknod["trace_lsm_inode_mknod"]
trace_lsm_inode_need_killpriv -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_need_killpriv["trace_lsm_inode_need_killpriv"]
trace_lsm_inode_notifysecctx -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_notifysecctx["trace_lsm_inode_notifysecctx"]
trace_lsm_inode_permission -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_permission["trace_lsm_inode_permission"]
trace_lsm_inode_post_setxattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_post_setxattr["trace_lsm_inode_post_setxattr"]
trace_lsm_inode_readlink -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_readlink["trace_lsm_inode_readlink"]
trace_lsm_inode_removexattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_removexattr["trace_lsm_inode_removexattr"]
trace_lsm_inode_rename -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_rename["trace_lsm_inode_rename"]
trace_lsm_inode_rmdir -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_rmdir["trace_lsm_inode_rmdir"]
trace_lsm_inode_setattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_setattr["trace_lsm_inode_setattr"]
trace_lsm_inode_setsecctx -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_setsecctx["trace_lsm_inode_setsecctx"]
trace_lsm_inode_setsecurity -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_setsecurity["trace_lsm_inode_setsecurity"]
trace_lsm_inode_setxattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_setxattr["trace_lsm_inode_setxattr"]
trace_lsm_inode_symlink -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_symlink["trace_lsm_inode_symlink"]
trace_lsm_inode_unlink -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_inode_unlink["trace_lsm_inode_unlink"]
trace_lsm_ipc_getsecid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_ipc_getsecid["trace_lsm_ipc_getsecid"]
trace_lsm_ipc_permission -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_ipc_permission["trace_lsm_ipc_permission"]
trace_lsm_ismaclabel -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_ismaclabel["trace_lsm_ismaclabel"]
trace_lsm_kernel_act_as -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_kernel_act_as["trace_lsm_kernel_act_as"]
trace_lsm_kernel_create_files_as -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_kernel_create_files_as["trace_lsm_kernel_create_files_as"]
trace_lsm_kernel_load_data -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_kernel_load_data["trace_lsm_kernel_load_data"]
trace_lsm_kernel_module_request -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_kernel_module_request["trace_lsm_kernel_module_request"]
trace_lsm_kernel_post_load_data -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_kernel_post_load_data["trace_lsm_kernel_post_load_data"]
trace_lsm_kernel_post_read_file -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_kernel_post_read_file["trace_lsm_kernel_post_read_file"]
trace_lsm_kernel_read_file -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_kernel_read_file["trace_lsm_kernel_read_file"]
trace_lsm_kernfs_init_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_kernfs_init_security["trace_lsm_kernfs_init_security"]
trace_lsm_mmap_addr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_mmap_addr["trace_lsm_mmap_addr"]
trace_lsm_mmap_file -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_mmap_file["trace_lsm_mmap_file"]
trace_lsm_move_mount -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_move_mount["trace_lsm_move_mount"]
trace_lsm_msg_msg_alloc_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_msg_msg_alloc_security["trace_lsm_msg_msg_alloc_security"]
trace_lsm_msg_msg_free_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_msg_msg_free_security["trace_lsm_msg_msg_free_security"]
trace_lsm_msg_queue_alloc_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_msg_queue_alloc_security["trace_lsm_msg_queue_alloc_security"]
trace_lsm_msg_queue_associate -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_msg_queue_associate["trace_lsm_msg_queue_associate"]
trace_lsm_msg_queue_free_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_msg_queue_free_security["trace_lsm_msg_queue_free_security"]
trace_lsm_msg_queue_msgctl -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_msg_queue_msgctl["trace_lsm_msg_queue_msgctl"]
trace_lsm_msg_queue_msgrcv -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_msg_queue_msgrcv["trace_lsm_msg_queue_msgrcv"]
trace_lsm_msg_queue_msgsnd -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_msg_queue_msgsnd["trace_lsm_msg_queue_msgsnd"]
trace_lsm_netlink_send -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_netlink_send["trace_lsm_netlink_send"]
trace_lsm_path_notify -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_path_notify["trace_lsm_path_notify"]
trace_lsm_ptrace_access_check -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_ptrace_access_check["trace_lsm_ptrace_access_check"]
trace_lsm_ptrace_traceme -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_ptrace_traceme["trace_lsm_ptrace_traceme"]
trace_lsm_quota_on -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_quota_on["trace_lsm_quota_on"]
trace_lsm_quotactl -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_quotactl["trace_lsm_quotactl"]
trace_lsm_release_secctx -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_release_secctx["trace_lsm_release_secctx"]
trace_lsm_sb_alloc_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_alloc_security["trace_lsm_sb_alloc_security"]
trace_lsm_sb_clone_mnt_opts -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_clone_mnt_opts["trace_lsm_sb_clone_mnt_opts"]
trace_lsm_sb_delete -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_delete["trace_lsm_sb_delete"]
trace_lsm_sb_eat_lsm_opts -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_eat_lsm_opts["trace_lsm_sb_eat_lsm_opts"]
trace_lsm_sb_free_mnt_opts -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_free_mnt_opts["trace_lsm_sb_free_mnt_opts"]
trace_lsm_sb_free_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_free_security["trace_lsm_sb_free_security"]
trace_lsm_sb_kern_mount -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_kern_mount["trace_lsm_sb_kern_mount"]
trace_lsm_sb_mnt_opts_compat -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_mnt_opts_compat["trace_lsm_sb_mnt_opts_compat"]
trace_lsm_sb_mount -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_mount["trace_lsm_sb_mount"]
trace_lsm_sb_pivotroot -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_pivotroot["trace_lsm_sb_pivotroot"]
trace_lsm_sb_remount -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_remount["trace_lsm_sb_remount"]
trace_lsm_sb_set_mnt_opts -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_set_mnt_opts["trace_lsm_sb_set_mnt_opts"]
trace_lsm_sb_show_options -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_show_options["trace_lsm_sb_show_options"]
trace_lsm_sb_statfs -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_statfs["trace_lsm_sb_statfs"]
trace_lsm_sb_umount -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sb_umount["trace_lsm_sb_umount"]
trace_lsm_secctx_to_secid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_secctx_to_secid["trace_lsm_secctx_to_secid"]
trace_lsm_secid_to_secctx -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_secid_to_secctx["trace_lsm_secid_to_secctx"]
trace_lsm_sem_alloc_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sem_alloc_security["trace_lsm_sem_alloc_security"]
trace_lsm_sem_associate -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sem_associate["trace_lsm_sem_associate"]
trace_lsm_sem_free_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sem_free_security["trace_lsm_sem_free_security"]
trace_lsm_sem_semctl -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sem_semctl["trace_lsm_sem_semctl"]
trace_lsm_sem_semop -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_sem_semop["trace_lsm_sem_semop"]
trace_lsm_setprocattr -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_setprocattr["trace_lsm_setprocattr"]
trace_lsm_settime -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_settime["trace_lsm_settime"]
trace_lsm_shm_alloc_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_shm_alloc_security["trace_lsm_shm_alloc_security"]
trace_lsm_shm_associate -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_shm_associate["trace_lsm_shm_associate"]
trace_lsm_shm_free_security -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_shm_free_security["trace_lsm_shm_free_security"]
trace_lsm_shm_shmat -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_shm_shmat["trace_lsm_shm_shmat"]
trace_lsm_shm_shmctl -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_shm_shmctl["trace_lsm_shm_shmctl"]
trace_lsm_syslog -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_syslog["trace_lsm_syslog"]
trace_lsm_task_alloc -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_alloc["trace_lsm_task_alloc"]
trace_lsm_task_fix_setgid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_fix_setgid["trace_lsm_task_fix_setgid"]
trace_lsm_task_fix_setuid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_fix_setuid["trace_lsm_task_fix_setuid"]
trace_lsm_task_free -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_free["trace_lsm_task_free"]
trace_lsm_task_getioprio -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_getioprio["trace_lsm_task_getioprio"]
trace_lsm_task_getpgid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_getpgid["trace_lsm_task_getpgid"]
trace_lsm_task_getscheduler -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_getscheduler["trace_lsm_task_getscheduler"]
trace_lsm_task_getsecid_obj -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_getsecid_obj["trace_lsm_task_getsecid_obj"]
trace_lsm_task_getsid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_getsid["trace_lsm_task_getsid"]
trace_lsm_task_kill -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_kill["trace_lsm_task_kill"]
trace_lsm_task_movememory -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_movememory["trace_lsm_task_movememory"]
trace_lsm_task_prctl -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_prctl["trace_lsm_task_prctl"]
trace_lsm_task_prlimit -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_prlimit["trace_lsm_task_prlimit"]
trace_lsm_task_setioprio -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_setioprio["trace_lsm_task_setioprio"]
trace_lsm_task_setnice -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_setnice["trace_lsm_task_setnice"]
trace_lsm_task_setpgid -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_setpgid["trace_lsm_task_setpgid"]
trace_lsm_task_setrlimit -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_setrlimit["trace_lsm_task_setrlimit"]
trace_lsm_task_setscheduler -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_setscheduler["trace_lsm_task_setscheduler"]
trace_lsm_task_to_inode -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_task_to_inode["trace_lsm_task_to_inode"]
trace_lsm_vm_enough_memory -- "Lookup" --> gadget_mntns_filter_map
trace_lsm_vm_enough_memory["trace_lsm_vm_enough_memory"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant trace_lsm_binder_set_context_mgr
participant trace_lsm_binder_transaction
participant trace_lsm_binder_transfer_binder
participant trace_lsm_binder_transfer_file
participant trace_lsm_bprm_check_security
participant trace_lsm_bprm_committed_creds
participant trace_lsm_bprm_committing_creds
participant trace_lsm_bprm_creds_for_exec
participant trace_lsm_bprm_creds_from_file
participant trace_lsm_capable
participant trace_lsm_capget
participant trace_lsm_capset
participant trace_lsm_cred_alloc_blank
participant trace_lsm_cred_free
participant trace_lsm_cred_getsecid
participant trace_lsm_cred_prepare
participant trace_lsm_cred_transfer
participant trace_lsm_d_instantiate
participant trace_lsm_dentry_create_files_as
participant trace_lsm_dentry_init_security
participant trace_lsm_file_alloc_security
participant trace_lsm_file_fcntl
participant trace_lsm_file_free_security
participant trace_lsm_file_ioctl
participant trace_lsm_file_lock
participant trace_lsm_file_mprotect
participant trace_lsm_file_open
participant trace_lsm_file_permission
participant trace_lsm_file_receive
participant trace_lsm_file_send_sigiotask
participant trace_lsm_file_set_fowner
participant trace_lsm_fs_context_dup
participant trace_lsm_fs_context_parse_param
participant trace_lsm_getprocattr
participant trace_lsm_inode_alloc_security
participant trace_lsm_inode_copy_up
participant trace_lsm_inode_copy_up_xattr
participant trace_lsm_inode_create
participant trace_lsm_inode_follow_link
participant trace_lsm_inode_free_security
participant trace_lsm_inode_getattr
participant trace_lsm_inode_getsecctx
participant trace_lsm_inode_getsecid
participant trace_lsm_inode_getsecurity
participant trace_lsm_inode_getxattr
participant trace_lsm_inode_init_security
participant trace_lsm_inode_init_security_anon
participant trace_lsm_inode_invalidate_secctx
participant trace_lsm_inode_killpriv
participant trace_lsm_inode_link
participant trace_lsm_inode_listsecurity
participant trace_lsm_inode_listxattr
participant trace_lsm_inode_mkdir
participant trace_lsm_inode_mknod
participant trace_lsm_inode_need_killpriv
participant trace_lsm_inode_notifysecctx
participant trace_lsm_inode_permission
participant trace_lsm_inode_post_setxattr
participant trace_lsm_inode_readlink
participant trace_lsm_inode_removexattr
participant trace_lsm_inode_rename
participant trace_lsm_inode_rmdir
participant trace_lsm_inode_setattr
participant trace_lsm_inode_setsecctx
participant trace_lsm_inode_setsecurity
participant trace_lsm_inode_setxattr
participant trace_lsm_inode_symlink
participant trace_lsm_inode_unlink
participant trace_lsm_ipc_getsecid
participant trace_lsm_ipc_permission
participant trace_lsm_ismaclabel
participant trace_lsm_kernel_act_as
participant trace_lsm_kernel_create_files_as
participant trace_lsm_kernel_load_data
participant trace_lsm_kernel_module_request
participant trace_lsm_kernel_post_load_data
participant trace_lsm_kernel_post_read_file
participant trace_lsm_kernel_read_file
participant trace_lsm_kernfs_init_security
participant trace_lsm_mmap_addr
participant trace_lsm_mmap_file
participant trace_lsm_move_mount
participant trace_lsm_msg_msg_alloc_security
participant trace_lsm_msg_msg_free_security
participant trace_lsm_msg_queue_alloc_security
participant trace_lsm_msg_queue_associate
participant trace_lsm_msg_queue_free_security
participant trace_lsm_msg_queue_msgctl
participant trace_lsm_msg_queue_msgrcv
participant trace_lsm_msg_queue_msgsnd
participant trace_lsm_netlink_send
participant trace_lsm_path_notify
participant trace_lsm_ptrace_access_check
participant trace_lsm_ptrace_traceme
participant trace_lsm_quota_on
participant trace_lsm_quotactl
participant trace_lsm_release_secctx
participant trace_lsm_sb_alloc_security
participant trace_lsm_sb_clone_mnt_opts
participant trace_lsm_sb_delete
participant trace_lsm_sb_eat_lsm_opts
participant trace_lsm_sb_free_mnt_opts
participant trace_lsm_sb_free_security
participant trace_lsm_sb_kern_mount
participant trace_lsm_sb_mnt_opts_compat
participant trace_lsm_sb_mount
participant trace_lsm_sb_pivotroot
participant trace_lsm_sb_remount
participant trace_lsm_sb_set_mnt_opts
participant trace_lsm_sb_show_options
participant trace_lsm_sb_statfs
participant trace_lsm_sb_umount
participant trace_lsm_secctx_to_secid
participant trace_lsm_secid_to_secctx
participant trace_lsm_sem_alloc_security
participant trace_lsm_sem_associate
participant trace_lsm_sem_free_security
participant trace_lsm_sem_semctl
participant trace_lsm_sem_semop
participant trace_lsm_setprocattr
participant trace_lsm_settime
participant trace_lsm_shm_alloc_security
participant trace_lsm_shm_associate
participant trace_lsm_shm_free_security
participant trace_lsm_shm_shmat
participant trace_lsm_shm_shmctl
participant trace_lsm_syslog
participant trace_lsm_task_alloc
participant trace_lsm_task_fix_setgid
participant trace_lsm_task_fix_setuid
participant trace_lsm_task_free
participant trace_lsm_task_getioprio
participant trace_lsm_task_getpgid
participant trace_lsm_task_getscheduler
participant trace_lsm_task_getsecid_obj
participant trace_lsm_task_getsid
participant trace_lsm_task_kill
participant trace_lsm_task_movememory
participant trace_lsm_task_prctl
participant trace_lsm_task_prlimit
participant trace_lsm_task_setioprio
participant trace_lsm_task_setnice
participant trace_lsm_task_setpgid
participant trace_lsm_task_setrlimit
participant trace_lsm_task_setscheduler
participant trace_lsm_task_to_inode
participant trace_lsm_vm_enough_memory
end
box eBPF Maps
participant gadget_mntns_filter_map
end
trace_lsm_binder_set_context_mgr->>gadget_mntns_filter_map: Lookup
trace_lsm_binder_transaction->>gadget_mntns_filter_map: Lookup
trace_lsm_binder_transfer_binder->>gadget_mntns_filter_map: Lookup
trace_lsm_binder_transfer_file->>gadget_mntns_filter_map: Lookup
trace_lsm_bprm_check_security->>gadget_mntns_filter_map: Lookup
trace_lsm_bprm_committed_creds->>gadget_mntns_filter_map: Lookup
trace_lsm_bprm_committing_creds->>gadget_mntns_filter_map: Lookup
trace_lsm_bprm_creds_for_exec->>gadget_mntns_filter_map: Lookup
trace_lsm_bprm_creds_from_file->>gadget_mntns_filter_map: Lookup
trace_lsm_capable->>gadget_mntns_filter_map: Lookup
trace_lsm_capget->>gadget_mntns_filter_map: Lookup
trace_lsm_capset->>gadget_mntns_filter_map: Lookup
trace_lsm_cred_alloc_blank->>gadget_mntns_filter_map: Lookup
trace_lsm_cred_free->>gadget_mntns_filter_map: Lookup
trace_lsm_cred_getsecid->>gadget_mntns_filter_map: Lookup
trace_lsm_cred_prepare->>gadget_mntns_filter_map: Lookup
trace_lsm_cred_transfer->>gadget_mntns_filter_map: Lookup
trace_lsm_d_instantiate->>gadget_mntns_filter_map: Lookup
trace_lsm_dentry_create_files_as->>gadget_mntns_filter_map: Lookup
trace_lsm_dentry_init_security->>gadget_mntns_filter_map: Lookup
trace_lsm_file_alloc_security->>gadget_mntns_filter_map: Lookup
trace_lsm_file_fcntl->>gadget_mntns_filter_map: Lookup
trace_lsm_file_free_security->>gadget_mntns_filter_map: Lookup
trace_lsm_file_ioctl->>gadget_mntns_filter_map: Lookup
trace_lsm_file_lock->>gadget_mntns_filter_map: Lookup
trace_lsm_file_mprotect->>gadget_mntns_filter_map: Lookup
trace_lsm_file_open->>gadget_mntns_filter_map: Lookup
trace_lsm_file_permission->>gadget_mntns_filter_map: Lookup
trace_lsm_file_receive->>gadget_mntns_filter_map: Lookup
trace_lsm_file_send_sigiotask->>gadget_mntns_filter_map: Lookup
trace_lsm_file_set_fowner->>gadget_mntns_filter_map: Lookup
trace_lsm_fs_context_dup->>gadget_mntns_filter_map: Lookup
trace_lsm_fs_context_parse_param->>gadget_mntns_filter_map: Lookup
trace_lsm_getprocattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_alloc_security->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_copy_up->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_copy_up_xattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_create->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_follow_link->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_free_security->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_getattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_getsecctx->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_getsecid->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_getsecurity->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_getxattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_init_security->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_init_security_anon->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_invalidate_secctx->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_killpriv->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_link->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_listsecurity->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_listxattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_mkdir->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_mknod->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_need_killpriv->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_notifysecctx->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_permission->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_post_setxattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_readlink->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_removexattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_rename->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_rmdir->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_setattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_setsecctx->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_setsecurity->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_setxattr->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_symlink->>gadget_mntns_filter_map: Lookup
trace_lsm_inode_unlink->>gadget_mntns_filter_map: Lookup
trace_lsm_ipc_getsecid->>gadget_mntns_filter_map: Lookup
trace_lsm_ipc_permission->>gadget_mntns_filter_map: Lookup
trace_lsm_ismaclabel->>gadget_mntns_filter_map: Lookup
trace_lsm_kernel_act_as->>gadget_mntns_filter_map: Lookup
trace_lsm_kernel_create_files_as->>gadget_mntns_filter_map: Lookup
trace_lsm_kernel_load_data->>gadget_mntns_filter_map: Lookup
trace_lsm_kernel_module_request->>gadget_mntns_filter_map: Lookup
trace_lsm_kernel_post_load_data->>gadget_mntns_filter_map: Lookup
trace_lsm_kernel_post_read_file->>gadget_mntns_filter_map: Lookup
trace_lsm_kernel_read_file->>gadget_mntns_filter_map: Lookup
trace_lsm_kernfs_init_security->>gadget_mntns_filter_map: Lookup
trace_lsm_mmap_addr->>gadget_mntns_filter_map: Lookup
trace_lsm_mmap_file->>gadget_mntns_filter_map: Lookup
trace_lsm_move_mount->>gadget_mntns_filter_map: Lookup
trace_lsm_msg_msg_alloc_security->>gadget_mntns_filter_map: Lookup
trace_lsm_msg_msg_free_security->>gadget_mntns_filter_map: Lookup
trace_lsm_msg_queue_alloc_security->>gadget_mntns_filter_map: Lookup
trace_lsm_msg_queue_associate->>gadget_mntns_filter_map: Lookup
trace_lsm_msg_queue_free_security->>gadget_mntns_filter_map: Lookup
trace_lsm_msg_queue_msgctl->>gadget_mntns_filter_map: Lookup
trace_lsm_msg_queue_msgrcv->>gadget_mntns_filter_map: Lookup
trace_lsm_msg_queue_msgsnd->>gadget_mntns_filter_map: Lookup
trace_lsm_netlink_send->>gadget_mntns_filter_map: Lookup
trace_lsm_path_notify->>gadget_mntns_filter_map: Lookup
trace_lsm_ptrace_access_check->>gadget_mntns_filter_map: Lookup
trace_lsm_ptrace_traceme->>gadget_mntns_filter_map: Lookup
trace_lsm_quota_on->>gadget_mntns_filter_map: Lookup
trace_lsm_quotactl->>gadget_mntns_filter_map: Lookup
trace_lsm_release_secctx->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_alloc_security->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_clone_mnt_opts->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_delete->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_eat_lsm_opts->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_free_mnt_opts->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_free_security->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_kern_mount->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_mnt_opts_compat->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_mount->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_pivotroot->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_remount->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_set_mnt_opts->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_show_options->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_statfs->>gadget_mntns_filter_map: Lookup
trace_lsm_sb_umount->>gadget_mntns_filter_map: Lookup
trace_lsm_secctx_to_secid->>gadget_mntns_filter_map: Lookup
trace_lsm_secid_to_secctx->>gadget_mntns_filter_map: Lookup
trace_lsm_sem_alloc_security->>gadget_mntns_filter_map: Lookup
trace_lsm_sem_associate->>gadget_mntns_filter_map: Lookup
trace_lsm_sem_free_security->>gadget_mntns_filter_map: Lookup
trace_lsm_sem_semctl->>gadget_mntns_filter_map: Lookup
trace_lsm_sem_semop->>gadget_mntns_filter_map: Lookup
trace_lsm_setprocattr->>gadget_mntns_filter_map: Lookup
trace_lsm_settime->>gadget_mntns_filter_map: Lookup
trace_lsm_shm_alloc_security->>gadget_mntns_filter_map: Lookup
trace_lsm_shm_associate->>gadget_mntns_filter_map: Lookup
trace_lsm_shm_free_security->>gadget_mntns_filter_map: Lookup
trace_lsm_shm_shmat->>gadget_mntns_filter_map: Lookup
trace_lsm_shm_shmctl->>gadget_mntns_filter_map: Lookup
trace_lsm_syslog->>gadget_mntns_filter_map: Lookup
trace_lsm_task_alloc->>gadget_mntns_filter_map: Lookup
trace_lsm_task_fix_setgid->>gadget_mntns_filter_map: Lookup
trace_lsm_task_fix_setuid->>gadget_mntns_filter_map: Lookup
trace_lsm_task_free->>gadget_mntns_filter_map: Lookup
trace_lsm_task_getioprio->>gadget_mntns_filter_map: Lookup
trace_lsm_task_getpgid->>gadget_mntns_filter_map: Lookup
trace_lsm_task_getscheduler->>gadget_mntns_filter_map: Lookup
trace_lsm_task_getsecid_obj->>gadget_mntns_filter_map: Lookup
trace_lsm_task_getsid->>gadget_mntns_filter_map: Lookup
trace_lsm_task_kill->>gadget_mntns_filter_map: Lookup
trace_lsm_task_movememory->>gadget_mntns_filter_map: Lookup
trace_lsm_task_prctl->>gadget_mntns_filter_map: Lookup
trace_lsm_task_prlimit->>gadget_mntns_filter_map: Lookup
trace_lsm_task_setioprio->>gadget_mntns_filter_map: Lookup
trace_lsm_task_setnice->>gadget_mntns_filter_map: Lookup
trace_lsm_task_setpgid->>gadget_mntns_filter_map: Lookup
trace_lsm_task_setrlimit->>gadget_mntns_filter_map: Lookup
trace_lsm_task_setscheduler->>gadget_mntns_filter_map: Lookup
trace_lsm_task_to_inode->>gadget_mntns_filter_map: Lookup
trace_lsm_vm_enough_memory->>gadget_mntns_filter_map: Lookup
```
