# audit_seccomp

The audit seccomp gadget provides a stream of events with syscalls that had
their seccomp filters generating an audit log. An audit log can be generated in
one of these two conditions:

* The Seccomp profile has the flag `SECCOMP_FILTER_FLAG_LOG` (supported from
  [runc v1.2.0](https://github.com/opencontainers/runc/releases/tag/v1.2.0),
  see [runc#3390](https://github.com/opencontainers/runc/pull/3390)) and returns
  any action other than `SECCOMP_RET_ALLOW`.
* The Seccomp profile does not have the flag `SECCOMP_FILTER_FLAG_LOG` but
  returns `SCMP_ACT_LOG` or `SCMP_ACT_KILL*`.

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/audit_seccomp
