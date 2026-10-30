#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

/* Disposable fixture consumer only. It never changes the mapped file and
 * cannot select anything outside the explicit current user's fixture root. */
int main(int argc, char **argv) {
    alarm(30);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 3 || getuid() == 0 || getuid() != geteuid()) return 77;
    const char *base = getenv("APP_SWEEP_FIXTURES");
    char root[PATH_MAX], path[PATH_MAX];
    if (!base || !realpath(base, root) || !realpath(argv[2], path) ||
        strncmp(path, root, strlen(root)) || path[strlen(root)] != '/') return 77;
    int shared = !strcmp(argv[1], "shared-write");
    int writable = shared || !strcmp(argv[1], "private-write");
    int executable_capable = !strcmp(argv[1], "private-executable-capable");
    if (!shared && !writable && !executable_capable && strcmp(argv[1], "private")) return 64;
    int fd = open(path, (shared ? O_RDWR : O_RDONLY) | O_NOFOLLOW);
    struct stat s;
    if (fd < 0 || fstat(fd, &s) || !S_ISREG(s.st_mode) || s.st_uid != getuid() ||
        s.st_nlink != 1 || s.st_size <= 0 || s.st_size > 2 * 1024 * 1024) return 77;
    size_t length = (size_t)s.st_size;
    void *mapped = mmap(NULL, length, PROT_READ | (writable ? PROT_WRITE : 0),
                        shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) return 78;
    /* Match the observed system data mapping's maximum READ|WRITE protection.
     * This only removes execute permission from this child's own mapping. */
    if (!executable_capable && mach_vm_protect(mach_task_self(), (mach_vm_address_t)mapped,
        (mach_vm_size_t)length, TRUE, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) return 78;
    void *original = malloc(length);
    if (!original) return 78;
    memcpy(original, mapped, length);
    puts("READY");
    struct proc_regionwithpathinfo region = {0};
    int observed = proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO, (uint64_t)mapped, &region, sizeof(region));
    printf("MAP bytes=%d protection=%u max=%u share=%u\n", observed,
           region.prp_prinfo.pri_protection, region.prp_prinfo.pri_max_protection, region.prp_prinfo.pri_share_mode);
    char line[32];
    while (fgets(line, sizeof(line), stdin)) {
        if (strcmp(line, "verify\n")) { free(original); munmap(mapped, length); return 64; }
        puts(memcmp(original, mapped, length) ? "CHANGED" : "UNCHANGED");
    }
    free(original);
    munmap(mapped, length);
    return 0;
}
