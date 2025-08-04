# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
crypto_context[("crypto_context")]
events[("events")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
ssl_context[("ssl_context")]
trace_sched_process_exit -- "Delete" --> ssl_context
trace_sched_process_exit -- "Delete" --> crypto_context
trace_sched_process_exit["trace_sched_process_exit"]
trace_uprobe_libcrypto_RSA_sign -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_RSA_sign -- "Update" --> crypto_context
trace_uprobe_libcrypto_RSA_sign["trace_uprobe_libcrypto_RSA_sign"]
trace_uprobe_libcrypto_RSA_verify -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_RSA_verify -- "Update" --> crypto_context
trace_uprobe_libcrypto_RSA_verify["trace_uprobe_libcrypto_RSA_verify"]
trace_uprobe_libcrypto_ossl_ecdh_compute_key -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_ossl_ecdh_compute_key -- "Update" --> crypto_context
trace_uprobe_libcrypto_ossl_ecdh_compute_key["trace_uprobe_libcrypto_ossl_ecdh_compute_key"]
trace_uprobe_libcrypto_ossl_ecdsa_sign -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_ossl_ecdsa_sign -- "Update" --> crypto_context
trace_uprobe_libcrypto_ossl_ecdsa_sign["trace_uprobe_libcrypto_ossl_ecdsa_sign"]
trace_uprobe_libcrypto_ossl_ecdsa_verify -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_ossl_ecdsa_verify -- "Update" --> crypto_context
trace_uprobe_libcrypto_ossl_ecdsa_verify["trace_uprobe_libcrypto_ossl_ecdsa_verify"]
trace_uprobe_libcrypto_rsa_ossl_private_decrypt -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_rsa_ossl_private_decrypt -- "Update" --> crypto_context
trace_uprobe_libcrypto_rsa_ossl_private_decrypt["trace_uprobe_libcrypto_rsa_ossl_private_decrypt"]
trace_uprobe_libcrypto_rsa_ossl_private_encrypt -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_rsa_ossl_private_encrypt -- "Update" --> crypto_context
trace_uprobe_libcrypto_rsa_ossl_private_encrypt["trace_uprobe_libcrypto_rsa_ossl_private_encrypt"]
trace_uprobe_libcrypto_rsa_ossl_public_decrypt -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_rsa_ossl_public_decrypt -- "Update" --> crypto_context
trace_uprobe_libcrypto_rsa_ossl_public_decrypt["trace_uprobe_libcrypto_rsa_ossl_public_decrypt"]
trace_uprobe_libcrypto_rsa_ossl_public_encrypt -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libcrypto_rsa_ossl_public_encrypt -- "Update" --> crypto_context
trace_uprobe_libcrypto_rsa_ossl_public_encrypt["trace_uprobe_libcrypto_rsa_ossl_public_encrypt"]
trace_uprobe_libgnutls_gnutls_record_recv -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libgnutls_gnutls_record_recv -- "Update" --> ssl_context
trace_uprobe_libgnutls_gnutls_record_recv["trace_uprobe_libgnutls_gnutls_record_recv"]
trace_uprobe_libgnutls_gnutls_record_send -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libgnutls_gnutls_record_send -- "Update" --> ssl_context
trace_uprobe_libgnutls_gnutls_record_send["trace_uprobe_libgnutls_gnutls_record_send"]
trace_uprobe_libnss_PR_Read -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libnss_PR_Read -- "Update" --> ssl_context
trace_uprobe_libnss_PR_Read["trace_uprobe_libnss_PR_Read"]
trace_uprobe_libnss_PR_Recv -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libnss_PR_Recv -- "Update" --> ssl_context
trace_uprobe_libnss_PR_Recv["trace_uprobe_libnss_PR_Recv"]
trace_uprobe_libnss_PR_Send -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libnss_PR_Send -- "Update" --> ssl_context
trace_uprobe_libnss_PR_Send["trace_uprobe_libnss_PR_Send"]
trace_uprobe_libnss_PR_Write -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libnss_PR_Write -- "Update" --> ssl_context
trace_uprobe_libnss_PR_Write["trace_uprobe_libnss_PR_Write"]
trace_uprobe_libssl_SSL_do_handshake -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libssl_SSL_do_handshake -- "Update" --> ssl_context
trace_uprobe_libssl_SSL_do_handshake["trace_uprobe_libssl_SSL_do_handshake"]
trace_uprobe_libssl_SSL_read -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libssl_SSL_read -- "Update" --> ssl_context
trace_uprobe_libssl_SSL_read["trace_uprobe_libssl_SSL_read"]
trace_uprobe_libssl_SSL_write -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_libssl_SSL_write -- "Update" --> ssl_context
trace_uprobe_libssl_SSL_write["trace_uprobe_libssl_SSL_write"]
trace_uretprobe_libcrypto_RSA_sign -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_RSA_sign -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_RSA_sign -- "EventOutput" --> events
trace_uretprobe_libcrypto_RSA_sign["trace_uretprobe_libcrypto_RSA_sign"]
trace_uretprobe_libcrypto_RSA_verify -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_RSA_verify -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_RSA_verify -- "EventOutput" --> events
trace_uretprobe_libcrypto_RSA_verify["trace_uretprobe_libcrypto_RSA_verify"]
trace_uretprobe_libcrypto_ossl_ecdh_compute_key -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_ossl_ecdh_compute_key -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_ossl_ecdh_compute_key -- "EventOutput" --> events
trace_uretprobe_libcrypto_ossl_ecdh_compute_key["trace_uretprobe_libcrypto_ossl_ecdh_compute_key"]
trace_uretprobe_libcrypto_ossl_ecdsa_sign -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_ossl_ecdsa_sign -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_ossl_ecdsa_sign -- "EventOutput" --> events
trace_uretprobe_libcrypto_ossl_ecdsa_sign["trace_uretprobe_libcrypto_ossl_ecdsa_sign"]
trace_uretprobe_libcrypto_ossl_ecdsa_verify -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_ossl_ecdsa_verify -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_ossl_ecdsa_verify -- "EventOutput" --> events
trace_uretprobe_libcrypto_ossl_ecdsa_verify["trace_uretprobe_libcrypto_ossl_ecdsa_verify"]
trace_uretprobe_libcrypto_rsa_ossl_private_decrypt -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_rsa_ossl_private_decrypt -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_rsa_ossl_private_decrypt -- "EventOutput" --> events
trace_uretprobe_libcrypto_rsa_ossl_private_decrypt["trace_uretprobe_libcrypto_rsa_ossl_private_decrypt"]
trace_uretprobe_libcrypto_rsa_ossl_private_encrypt -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_rsa_ossl_private_encrypt -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_rsa_ossl_private_encrypt -- "EventOutput" --> events
trace_uretprobe_libcrypto_rsa_ossl_private_encrypt["trace_uretprobe_libcrypto_rsa_ossl_private_encrypt"]
trace_uretprobe_libcrypto_rsa_ossl_public_decrypt -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_rsa_ossl_public_decrypt -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_rsa_ossl_public_decrypt -- "EventOutput" --> events
trace_uretprobe_libcrypto_rsa_ossl_public_decrypt["trace_uretprobe_libcrypto_rsa_ossl_public_decrypt"]
trace_uretprobe_libcrypto_rsa_ossl_public_encrypt -- "Lookup+Delete" --> crypto_context
trace_uretprobe_libcrypto_rsa_ossl_public_encrypt -- "Lookup" --> gadget_heap
trace_uretprobe_libcrypto_rsa_ossl_public_encrypt -- "EventOutput" --> events
trace_uretprobe_libcrypto_rsa_ossl_public_encrypt["trace_uretprobe_libcrypto_rsa_ossl_public_encrypt"]
trace_uretprobe_libgnutls_gnutls_record_recv -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libgnutls_gnutls_record_recv -- "Lookup" --> gadget_heap
trace_uretprobe_libgnutls_gnutls_record_recv -- "EventOutput" --> events
trace_uretprobe_libgnutls_gnutls_record_recv["trace_uretprobe_libgnutls_gnutls_record_recv"]
trace_uretprobe_libgnutls_gnutls_record_send -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libgnutls_gnutls_record_send -- "Lookup" --> gadget_heap
trace_uretprobe_libgnutls_gnutls_record_send -- "EventOutput" --> events
trace_uretprobe_libgnutls_gnutls_record_send["trace_uretprobe_libgnutls_gnutls_record_send"]
trace_uretprobe_libnss_PR_Read -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libnss_PR_Read -- "Lookup" --> gadget_heap
trace_uretprobe_libnss_PR_Read -- "EventOutput" --> events
trace_uretprobe_libnss_PR_Read["trace_uretprobe_libnss_PR_Read"]
trace_uretprobe_libnss_PR_Recv -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libnss_PR_Recv -- "Lookup" --> gadget_heap
trace_uretprobe_libnss_PR_Recv -- "EventOutput" --> events
trace_uretprobe_libnss_PR_Recv["trace_uretprobe_libnss_PR_Recv"]
trace_uretprobe_libnss_PR_Send -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libnss_PR_Send -- "Lookup" --> gadget_heap
trace_uretprobe_libnss_PR_Send -- "EventOutput" --> events
trace_uretprobe_libnss_PR_Send["trace_uretprobe_libnss_PR_Send"]
trace_uretprobe_libnss_PR_Write -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libnss_PR_Write -- "Lookup" --> gadget_heap
trace_uretprobe_libnss_PR_Write -- "EventOutput" --> events
trace_uretprobe_libnss_PR_Write["trace_uretprobe_libnss_PR_Write"]
trace_uretprobe_libssl_SSL_do_handshake -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libssl_SSL_do_handshake -- "Lookup" --> gadget_heap
trace_uretprobe_libssl_SSL_do_handshake -- "EventOutput" --> events
trace_uretprobe_libssl_SSL_do_handshake["trace_uretprobe_libssl_SSL_do_handshake"]
trace_uretprobe_libssl_SSL_read -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libssl_SSL_read -- "Lookup" --> gadget_heap
trace_uretprobe_libssl_SSL_read -- "EventOutput" --> events
trace_uretprobe_libssl_SSL_read["trace_uretprobe_libssl_SSL_read"]
trace_uretprobe_libssl_SSL_write -- "Lookup+Delete" --> ssl_context
trace_uretprobe_libssl_SSL_write -- "Lookup" --> gadget_heap
trace_uretprobe_libssl_SSL_write -- "EventOutput" --> events
trace_uretprobe_libssl_SSL_write["trace_uretprobe_libssl_SSL_write"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant trace_sched_process_exit
participant trace_uprobe_libcrypto_RSA_sign
participant trace_uprobe_libcrypto_RSA_verify
participant trace_uprobe_libcrypto_ossl_ecdh_compute_key
participant trace_uprobe_libcrypto_ossl_ecdsa_sign
participant trace_uprobe_libcrypto_ossl_ecdsa_verify
participant trace_uprobe_libcrypto_rsa_ossl_private_decrypt
participant trace_uprobe_libcrypto_rsa_ossl_private_encrypt
participant trace_uprobe_libcrypto_rsa_ossl_public_decrypt
participant trace_uprobe_libcrypto_rsa_ossl_public_encrypt
participant trace_uprobe_libgnutls_gnutls_record_recv
participant trace_uprobe_libgnutls_gnutls_record_send
participant trace_uprobe_libnss_PR_Read
participant trace_uprobe_libnss_PR_Recv
participant trace_uprobe_libnss_PR_Send
participant trace_uprobe_libnss_PR_Write
participant trace_uprobe_libssl_SSL_do_handshake
participant trace_uprobe_libssl_SSL_read
participant trace_uprobe_libssl_SSL_write
participant trace_uretprobe_libcrypto_RSA_sign
participant trace_uretprobe_libcrypto_RSA_verify
participant trace_uretprobe_libcrypto_ossl_ecdh_compute_key
participant trace_uretprobe_libcrypto_ossl_ecdsa_sign
participant trace_uretprobe_libcrypto_ossl_ecdsa_verify
participant trace_uretprobe_libcrypto_rsa_ossl_private_decrypt
participant trace_uretprobe_libcrypto_rsa_ossl_private_encrypt
participant trace_uretprobe_libcrypto_rsa_ossl_public_decrypt
participant trace_uretprobe_libcrypto_rsa_ossl_public_encrypt
participant trace_uretprobe_libgnutls_gnutls_record_recv
participant trace_uretprobe_libgnutls_gnutls_record_send
participant trace_uretprobe_libnss_PR_Read
participant trace_uretprobe_libnss_PR_Recv
participant trace_uretprobe_libnss_PR_Send
participant trace_uretprobe_libnss_PR_Write
participant trace_uretprobe_libssl_SSL_do_handshake
participant trace_uretprobe_libssl_SSL_read
participant trace_uretprobe_libssl_SSL_write
end
box eBPF Maps
participant ssl_context
participant crypto_context
participant gadget_mntns_filter_map
participant gadget_heap
participant events
end
trace_sched_process_exit->>ssl_context: Delete
trace_sched_process_exit->>crypto_context: Delete
trace_uprobe_libcrypto_RSA_sign->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_RSA_sign->>crypto_context: Update
trace_uprobe_libcrypto_RSA_verify->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_RSA_verify->>crypto_context: Update
trace_uprobe_libcrypto_ossl_ecdh_compute_key->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_ossl_ecdh_compute_key->>crypto_context: Update
trace_uprobe_libcrypto_ossl_ecdsa_sign->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_ossl_ecdsa_sign->>crypto_context: Update
trace_uprobe_libcrypto_ossl_ecdsa_verify->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_ossl_ecdsa_verify->>crypto_context: Update
trace_uprobe_libcrypto_rsa_ossl_private_decrypt->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_rsa_ossl_private_decrypt->>crypto_context: Update
trace_uprobe_libcrypto_rsa_ossl_private_encrypt->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_rsa_ossl_private_encrypt->>crypto_context: Update
trace_uprobe_libcrypto_rsa_ossl_public_decrypt->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_rsa_ossl_public_decrypt->>crypto_context: Update
trace_uprobe_libcrypto_rsa_ossl_public_encrypt->>gadget_mntns_filter_map: Lookup
trace_uprobe_libcrypto_rsa_ossl_public_encrypt->>crypto_context: Update
trace_uprobe_libgnutls_gnutls_record_recv->>gadget_mntns_filter_map: Lookup
trace_uprobe_libgnutls_gnutls_record_recv->>ssl_context: Update
trace_uprobe_libgnutls_gnutls_record_send->>gadget_mntns_filter_map: Lookup
trace_uprobe_libgnutls_gnutls_record_send->>ssl_context: Update
trace_uprobe_libnss_PR_Read->>gadget_mntns_filter_map: Lookup
trace_uprobe_libnss_PR_Read->>ssl_context: Update
trace_uprobe_libnss_PR_Recv->>gadget_mntns_filter_map: Lookup
trace_uprobe_libnss_PR_Recv->>ssl_context: Update
trace_uprobe_libnss_PR_Send->>gadget_mntns_filter_map: Lookup
trace_uprobe_libnss_PR_Send->>ssl_context: Update
trace_uprobe_libnss_PR_Write->>gadget_mntns_filter_map: Lookup
trace_uprobe_libnss_PR_Write->>ssl_context: Update
trace_uprobe_libssl_SSL_do_handshake->>gadget_mntns_filter_map: Lookup
trace_uprobe_libssl_SSL_do_handshake->>ssl_context: Update
trace_uprobe_libssl_SSL_read->>gadget_mntns_filter_map: Lookup
trace_uprobe_libssl_SSL_read->>ssl_context: Update
trace_uprobe_libssl_SSL_write->>gadget_mntns_filter_map: Lookup
trace_uprobe_libssl_SSL_write->>ssl_context: Update
trace_uretprobe_libcrypto_RSA_sign->>crypto_context: Lookup
trace_uretprobe_libcrypto_RSA_sign->>gadget_heap: Lookup
trace_uretprobe_libcrypto_RSA_sign->>events: EventOutput
trace_uretprobe_libcrypto_RSA_sign->>crypto_context: Delete
trace_uretprobe_libcrypto_RSA_verify->>crypto_context: Lookup
trace_uretprobe_libcrypto_RSA_verify->>gadget_heap: Lookup
trace_uretprobe_libcrypto_RSA_verify->>events: EventOutput
trace_uretprobe_libcrypto_RSA_verify->>crypto_context: Delete
trace_uretprobe_libcrypto_ossl_ecdh_compute_key->>crypto_context: Lookup
trace_uretprobe_libcrypto_ossl_ecdh_compute_key->>gadget_heap: Lookup
trace_uretprobe_libcrypto_ossl_ecdh_compute_key->>events: EventOutput
trace_uretprobe_libcrypto_ossl_ecdh_compute_key->>crypto_context: Delete
trace_uretprobe_libcrypto_ossl_ecdsa_sign->>crypto_context: Lookup
trace_uretprobe_libcrypto_ossl_ecdsa_sign->>gadget_heap: Lookup
trace_uretprobe_libcrypto_ossl_ecdsa_sign->>events: EventOutput
trace_uretprobe_libcrypto_ossl_ecdsa_sign->>crypto_context: Delete
trace_uretprobe_libcrypto_ossl_ecdsa_verify->>crypto_context: Lookup
trace_uretprobe_libcrypto_ossl_ecdsa_verify->>gadget_heap: Lookup
trace_uretprobe_libcrypto_ossl_ecdsa_verify->>events: EventOutput
trace_uretprobe_libcrypto_ossl_ecdsa_verify->>crypto_context: Delete
trace_uretprobe_libcrypto_rsa_ossl_private_decrypt->>crypto_context: Lookup
trace_uretprobe_libcrypto_rsa_ossl_private_decrypt->>gadget_heap: Lookup
trace_uretprobe_libcrypto_rsa_ossl_private_decrypt->>events: EventOutput
trace_uretprobe_libcrypto_rsa_ossl_private_decrypt->>crypto_context: Delete
trace_uretprobe_libcrypto_rsa_ossl_private_encrypt->>crypto_context: Lookup
trace_uretprobe_libcrypto_rsa_ossl_private_encrypt->>gadget_heap: Lookup
trace_uretprobe_libcrypto_rsa_ossl_private_encrypt->>events: EventOutput
trace_uretprobe_libcrypto_rsa_ossl_private_encrypt->>crypto_context: Delete
trace_uretprobe_libcrypto_rsa_ossl_public_decrypt->>crypto_context: Lookup
trace_uretprobe_libcrypto_rsa_ossl_public_decrypt->>gadget_heap: Lookup
trace_uretprobe_libcrypto_rsa_ossl_public_decrypt->>events: EventOutput
trace_uretprobe_libcrypto_rsa_ossl_public_decrypt->>crypto_context: Delete
trace_uretprobe_libcrypto_rsa_ossl_public_encrypt->>crypto_context: Lookup
trace_uretprobe_libcrypto_rsa_ossl_public_encrypt->>gadget_heap: Lookup
trace_uretprobe_libcrypto_rsa_ossl_public_encrypt->>events: EventOutput
trace_uretprobe_libcrypto_rsa_ossl_public_encrypt->>crypto_context: Delete
trace_uretprobe_libgnutls_gnutls_record_recv->>ssl_context: Lookup
trace_uretprobe_libgnutls_gnutls_record_recv->>gadget_heap: Lookup
trace_uretprobe_libgnutls_gnutls_record_recv->>events: EventOutput
trace_uretprobe_libgnutls_gnutls_record_recv->>ssl_context: Delete
trace_uretprobe_libgnutls_gnutls_record_send->>ssl_context: Lookup
trace_uretprobe_libgnutls_gnutls_record_send->>gadget_heap: Lookup
trace_uretprobe_libgnutls_gnutls_record_send->>events: EventOutput
trace_uretprobe_libgnutls_gnutls_record_send->>ssl_context: Delete
trace_uretprobe_libnss_PR_Read->>ssl_context: Lookup
trace_uretprobe_libnss_PR_Read->>gadget_heap: Lookup
trace_uretprobe_libnss_PR_Read->>events: EventOutput
trace_uretprobe_libnss_PR_Read->>ssl_context: Delete
trace_uretprobe_libnss_PR_Recv->>ssl_context: Lookup
trace_uretprobe_libnss_PR_Recv->>gadget_heap: Lookup
trace_uretprobe_libnss_PR_Recv->>events: EventOutput
trace_uretprobe_libnss_PR_Recv->>ssl_context: Delete
trace_uretprobe_libnss_PR_Send->>ssl_context: Lookup
trace_uretprobe_libnss_PR_Send->>gadget_heap: Lookup
trace_uretprobe_libnss_PR_Send->>events: EventOutput
trace_uretprobe_libnss_PR_Send->>ssl_context: Delete
trace_uretprobe_libnss_PR_Write->>ssl_context: Lookup
trace_uretprobe_libnss_PR_Write->>gadget_heap: Lookup
trace_uretprobe_libnss_PR_Write->>events: EventOutput
trace_uretprobe_libnss_PR_Write->>ssl_context: Delete
trace_uretprobe_libssl_SSL_do_handshake->>ssl_context: Lookup
trace_uretprobe_libssl_SSL_do_handshake->>gadget_heap: Lookup
trace_uretprobe_libssl_SSL_do_handshake->>events: EventOutput
trace_uretprobe_libssl_SSL_do_handshake->>ssl_context: Delete
trace_uretprobe_libssl_SSL_read->>ssl_context: Lookup
trace_uretprobe_libssl_SSL_read->>gadget_heap: Lookup
trace_uretprobe_libssl_SSL_read->>events: EventOutput
trace_uretprobe_libssl_SSL_read->>ssl_context: Delete
trace_uretprobe_libssl_SSL_write->>ssl_context: Lookup
trace_uretprobe_libssl_SSL_write->>gadget_heap: Lookup
trace_uretprobe_libssl_SSL_write->>events: EventOutput
trace_uretprobe_libssl_SSL_write->>ssl_context: Delete
```
