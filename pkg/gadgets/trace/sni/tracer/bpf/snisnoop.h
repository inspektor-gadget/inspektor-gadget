#ifndef GADGET_SNISNOOP_H
#define GADGET_SNISNOOP_H

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x1
#define TLS_EXTENSION_SERVER_NAME 0x0
// TODO: Figure out real max number according to RFC.
#define TLS_MAX_EXTENSION_COUNT 20
// TODO: figure out the right value.
#define TLS_MAX_SERVER_NAME_LEN 128

// The length of the session ID length field.
#define TLS_SESSION_ID_LENGTH_LEN 1
// The length of the cipher suites length field.
#define TLS_CIPHER_SUITES_LENGTH_LEN 2
// The length of the compression methods length field.
#define TLS_COMPRESSION_METHODS_LENGTH_LEN 1
// The length of the extensions length field.
#define TLS_EXTENSIONS_LENGTH_LEN 2
// The length of the extension type field.
#define TLS_EXTENSION_TYPE_LEN 2
// The length of the extension length field (a single extension).
#define TLS_EXTENSION_LENGTH_LEN 2

// The offset of the server name length field from the start of the server_name
// TLS extension.
#define TLS_SERVER_NAME_LENGTH_OFF 7
// The offset of the server name field from the start of the server_name TLS
// extension.
#define TLS_SERVER_NAME_OFF 9

// The offset of the handshake type field from the start of the TLS payload.
#define TLS_HANDSHAKE_TYPE_OFF 5
// The offset of the session ID length field from the start of the TLS payload.
#define TLS_SESSION_ID_LENGTH_OFF 43

#define TASK_COMM_LEN	16

struct event_t {
	__u64 mount_ns_id;
	__u32 pid;
	__u32 tid;
	__u8 task[TASK_COMM_LEN];
	__u8 name[TLS_MAX_SERVER_NAME_LEN];
	__u64 timestamp;
};

#endif
