// Independently authored disposable-VM acceptance consumer. This is never
// shipped in App Sweep and accepts no filesystem path or privileged operation.
#import <Foundation/Foundation.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int owned_directory(int parent, const char *name) {
    if (mkdirat(parent, name, 0700) != 0 && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat node;
    if (fd < 0) return -1;
    if (fstat(fd, &node) != 0 || node.st_uid != 0 || !S_ISDIR(node.st_mode) || (node.st_mode & 077) != 0) {
        close(fd); return -1;
    }
    return fd;
}
static int write_fixture(int parent, const char *name, NSData *data, BOOL old) {
    int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno == EEXIST) fd = openat(parent, name, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat node;
    int result = -1;
    if (fstat(fd, &node) == 0 && S_ISREG(node.st_mode) && node.st_uid == 0 && node.st_nlink == 1 &&
        (node.st_mode & 077) == 0 && ftruncate(fd, 0) == 0) {
        const uint8_t *bytes = data.bytes;
        size_t offset = 0;
        while (offset < data.length) {
            ssize_t count = write(fd, bytes + offset, data.length - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            offset += (size_t)count;
        }
        if (offset == data.length && fsync(fd) == 0) {
            struct timespec dates[2];
            dates[0].tv_sec = dates[1].tv_sec = time(NULL) - (old ? 40 * 86400 : 0);
            dates[0].tv_nsec = dates[1].tv_nsec = 0;
            result = futimens(fd, dates);
        }
    }
    close(fd); return result;
}
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3 || strcmp(argv[1], "--generate") != 0 || !argv[2][0] || strlen(argv[2]) > 6) return 64;
        for (const char *p = argv[2]; *p; ++p) if (*p < '0' || *p > '9') return 64;
        unsigned long generation = strtoul(argv[2], NULL, 10);
        if (generation == 0 || generation > 999999) return 64;
        if (getuid() != 0 || geteuid() != 0) { fputs("Disposable VM root acceptance consumer only\n", stderr); return 77; }
        char model[128] = {0}; size_t size = sizeof(model);
        if (sysctlbyname("hw.model", model, &size, NULL, 0) != 0 || strcmp(model, "VirtualMac2,1") != 0) return 77;
        NSBundle *bundle = NSBundle.mainBundle;
        NSString *raw = [bundle objectForInfoDictionaryKey:@"AppSweepAcceptanceNonce"];
        NSUUID *nonce = [[NSUUID alloc] initWithUUIDString:raw];
        if (!nonce || ![raw isEqualToString:nonce.UUIDString]) return 77;
        NSString *identifier = [@"org.example.disposable.systemconsumer." stringByAppendingString:nonce.UUIDString.lowercaseString];
        NSString *leaf = [NSString stringWithFormat:@"DisposableSystemConsumer-%@.app", nonce.UUIDString];
        NSArray<NSString *> *parts = bundle.bundlePath.pathComponents;
        NSString *stage = bundle.bundlePath.stringByDeletingLastPathComponent;
        NSString *prefix = @"AppSweepSystemAcceptance-";
        NSString *stageName = stage.lastPathComponent;
        NSUUID *stageID = [stageName hasPrefix:prefix] ? [[NSUUID alloc] initWithUUIDString:[stageName substringFromIndex:prefix.length]] : nil;
        struct stat stageNode;
        // Root executes the exact copied bundle from its private sticky-parent
        // staging directory, never a user-replaceable /Applications entry.
        if (![bundle.bundleIdentifier isEqualToString:identifier] || ![bundle.bundlePath.lastPathComponent isEqualToString:leaf] ||
            parts.count != 5 || ![parts[1] isEqualToString:@"private"] || ![parts[2] isEqualToString:@"tmp"] || !stageID ||
            lstat(stage.fileSystemRepresentation, &stageNode) != 0 || !S_ISDIR(stageNode.st_mode) || stageNode.st_uid != 0 ||
            (stageNode.st_mode & 077) != 0) return 77;
        int library = open("/Library", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (library < 0) return 1;
        int caches = openat(library, "Caches", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int logs = openat(library, "Logs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int cache = caches < 0 ? -1 : owned_directory(caches, identifier.UTF8String);
        int log = logs < 0 ? -1 : owned_directory(logs, identifier.UTF8String);
        int result = 1;
        if (cache >= 0 && log >= 0) {
            NSData *data = [[NSString stringWithFormat:@"Owned disposable system consumer generation:%lu\n", generation] dataUsingEncoding:NSUTF8StringEncoding];
            if (write_fixture(cache, "cache.bin", data, NO) == 0 && write_fixture(log, "old-consumer.log", data, YES) == 0) result = 0;
        }
        if (cache >= 0) close(cache); if (log >= 0) close(log);
        if (caches >= 0) close(caches); if (logs >= 0) close(logs); close(library);
        return result;
    }
}
