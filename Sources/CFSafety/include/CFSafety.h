#ifndef AS_FS_H
#define AS_FS_H
#include <stdint.h>
#include <stddef.h>
typedef struct {
 uint64_t device, inode, links;
 uint32_t mode, owner;
 int64_t size, modified_seconds, modified_nanoseconds, changed_seconds, changed_nanoseconds;
 /* Persistent native volume identity; device remains the live syscall number. */
 char volume_uuid[37];
} ASIdentity;
typedef struct { const char *relative; ASIdentity identity; } ASVerifiedEntry;
typedef struct { uint32_t effective_uid, real_uid; int32_t pid; uint8_t audit_token[32]; } ASPeerIdentity;
typedef struct {
 int32_t pid;
 uint32_t real_uid, effective_uid;
 uint64_t started_seconds, started_microseconds;
} ASProcessBirth;
/* Read-only, same-account process metadata. Image role is not authentication:
 * caller must independently verify the live Apple code requirement. */
int as_process_birth(int32_t pid, ASProcessBirth *result);
/* Same-account argv and cwd only; never exports environment. Rechecks birth.
 * Nonnegative bitmask: 0 = read; bit 2 = NODE_OPTIONS/NODE_PATH;
 * bit 4 = explicit download-module path in input (values never exported);
 * -1: incomplete, changed, unreadable. */
int as_process_arguments(int32_t pid, const ASProcessBirth *birth, char *arguments, size_t capacity, size_t *count, char *cwd, size_t cwd_capacity);
int as_javascript_runtime(int32_t pid);
int as_system_resource_reader_image(int32_t pid, const ASProcessBirth *birth);
/* 1: every matching vnode region is private/COW READ; 0: unsafe/absent;
 * -1: changed, failed or incomplete. No memory contents or process signals. */
int as_private_readonly_resource_mappings(int32_t pid, const ASIdentity *expected, const ASProcessBirth *birth);
int as_peer_identity(int fd, ASPeerIdentity *result);
int as_root_configuration_descriptor(int fd, int directory);
int as_unshared_node_descriptor(int fd, uint32_t owner);
int as_no_grant_acl_descriptor(int fd);
int as_connect_system_service_health(int timeout_ms);
int as_read_control_frame(int fd, void *output, size_t capacity, int timeout_ms, size_t *count);
int as_write_control_frame(int fd, const void *data, size_t count, int timeout_ms);
int as_connect_system_service(int timeout_ms);
int as_wait_control_frame(int fd, int timeout_ms);
int as_activate_system_listener(void);
/* Read-only kernel state for a descriptor in this process, not authority to
 * activate a daemon or accept a privileged peer. Darwin does not expose
 * SO_ACCEPTCONN through getsockopt; use its public socket_fdinfo instead. */
int as_unix_stream_listener(int fd);
/* -2 is a bounded idle timeout; -1 is a failed listener/accept. */
int as_accept_system_peer(int fd, int timeout_ms);
int as_open_directory(const char *path);
int as_identity_at(int directory, const char *name, ASIdentity *result);
int as_identity_fd(int fd, ASIdentity *result);
int as_installation_entries(int directory, void *output, size_t capacity, size_t *count, size_t *visited);
int as_directory_entries(int directory, void *output, size_t capacity, size_t maximum_entries, size_t *count);
int as_is_directory(const ASIdentity *identity);
int as_is_regular(const ASIdentity *identity);
int as_is_link(const ASIdentity *identity);
int as_private_directory(int parent, const char *name);
int as_private_descriptor(int fd);
int as_move_exclusive(int source, const char *name, int target, const char *new_name, const ASIdentity *expected);
/* Non-root, same-volume owned directories; second parent must be private.
 * 0: swap and persistence verified; -1: no swap; -2: outcome/persistence unknown.
 * Caller must journal intent and verify the allowed paths/ancestors, complete
 * trees, signatures and application activity. This API supplies no authority
 * for an application change. Never automatically retry after -2. */
int as_exchange_owned_directories(int first, const char *first_name, const ASIdentity *first_object,
 const ASIdentity *first_parent, int second, const char *second_name, const ASIdentity *second_object,
 const ASIdentity *second_parent);
/* Owned non-root node copy/fingerprint, never follows a symlink target.
 * Digest includes bytes/link text, mode/uid/gid/flags/mtime/ACL/xattrs, but no
 * inode/ctime/directory entries or link count. Caller validates whole topology.
 * Copy is exclusive for non-directories; directories must already be private.
 * 0 verified; -1 before creation/metadata mutation; -2 output partial/unknown.
 * Caller must persist intent first; retain and reconcile output on -2, never
 * retry/overwrite/delete automatically. These APIs grant no cleanup authority.
 * Limits: timeout 1..300000ms; bytes 1..1TiB; node metadata <=16MiB.
 */
int as_owned_node_digest(int parent, const char *name, const ASIdentity *expected,
 uint64_t maximum_bytes, int timeout_ms, void *output32);
/* Directory-only commitment for an application root across a move. Retains
 * mode/uid/gid/flags/mtime/ACL and all xattrs except OS-managed com.apple.macl.
 * Never edits that attribute. Identity must remain exact during the read.
 * This separate versioned digest does not change copy/full-node semantics. */
int as_owned_application_root_digest(int parent, const char *name, const ASIdentity *expected,
 int timeout_ms, void *output32);
/* Existing private destination directory only. OS metadata copy is unchanged;
 * comparison uses the application-root commitment above. All other node copies
 * keep their complete attribute comparison. No links/files or overwrite. */
int as_copy_owned_application_root(int source, const char *name, const ASIdentity *expected,
 int target, const char *new_name, int timeout_ms, ASIdentity *output_identity);
int as_copy_owned_node(int source, const char *name, const ASIdentity *expected,
 int target, const char *new_name, uint64_t maximum_bytes, int timeout_ms, ASIdentity *output_identity);
int as_write_atomic(int directory, const char *name, const void *data, size_t count);
int as_read_file(int directory, const char *name, void *data, size_t capacity, size_t *count);
int as_read_verified_file(int directory, const char *name, const ASIdentity *expected, void *data, size_t capacity, size_t *count);
int as_cache_file_metadata(int directory, const char *name, const ASIdentity *expected, uint32_t *group, void *attributes, size_t capacity, size_t *count);
int as_cache_node_metadata(int directory, const char *name, const ASIdentity *expected, uint32_t *group, void *attributes, size_t capacity, size_t *count);
int as_cache_node_metadata_with_flags(int directory, const char *name, const ASIdentity *expected, uint32_t *group, uint32_t *flags, void *attributes, size_t capacity, size_t *count);
int as_apply_private_node_metadata(int fd, const ASIdentity *expected, const ASIdentity *metadata, uint32_t group, const void *attributes, size_t attribute_count);
int as_apply_private_node_metadata_with_flags(int fd, const ASIdentity *expected, const ASIdentity *metadata, uint32_t group, uint32_t flags, const void *attributes, size_t attribute_count);
int as_link_private_regular(int source, const char *name, int target, const char *new_name, const ASIdentity *expected);
int as_write_recovered_regular(int directory, const char *name, const void *data, size_t count, const ASIdentity *metadata, uint32_t group, const void *attributes, size_t attribute_count);
int as_remove_verified(int directory, const char *name, const ASIdentity *expected, const ASVerifiedEntry *contents, size_t count);
int as_remove_verified_contained_links(int directory, const char *name, const ASIdentity *expected, const ASVerifiedEntry *contents, size_t count);
int as_remove_verified_application_links(int directory, const char *name, const ASIdentity *expected, const ASVerifiedEntry *contents, size_t count);
uint64_t as_available_bytes(int directory);
uint32_t as_current_uid(void);
int as_administrator_member(uint32_t uid);
int as_home_directory(char *output, size_t capacity);
int as_account_home_directory(uint32_t uid, char *output, size_t capacity);
int as_lock(int fd);
int as_run_process(const char *executable, char *const arguments[], char *output, size_t capacity, int timeout_ms, size_t *count, int merge_stderr, int *exit_status);
int as_run_process_with_input(const char *executable, char *const arguments[], char *output, size_t capacity, int timeout_ms, size_t *count, int merge_stderr, int *exit_status, int input_fd);
/* Independent staging only, not Mach-O validation or cleanup authority. Source
 * must be an owned single-link regular file; target a private same-volume dir.
 * 0: verified range+metadata copy; -1: no output created; -2: retained partial or
 * unconfirmed output. Caller must journal intent and recheck path ancestors.
 * Never overwrites/unlinks either object; maximum bounds the full source size. */
int as_copy_owned_regular_range(int source, const char *name, const ASIdentity *expected,
 int target, const char *new_name, uint64_t offset, uint64_t length,
 uint64_t maximum_bytes, int timeout_ms, ASIdentity *output_identity);
void as_close(int fd);
#endif
