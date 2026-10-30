// Test-only scheduling delay. Never linked into or shipped with the product.
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

static int delayed_usleep(useconds_t interval) {
    const char *requested = getenv("APP_SWEEP_RETRY_DELAY_THREAD");
    uint64_t thread = 0;
    pthread_threadid_np(NULL, &thread);
    if (interval == 20000 && requested && strtoull(requested, NULL, 10) == thread &&
        !getenv("APP_SWEEP_RETRY_DELAY_HIT")) {
        setenv("APP_SWEEP_RETRY_DELAY_HIT", "1", 1);
        struct timespec delay = {2, 150000000};
        while (nanosleep(&delay, &delay) != 0) {}
    }
    struct timespec pause = {interval / 1000000, (interval % 1000000) * 1000};
    int result;
    do { result = nanosleep(&pause, &pause); } while (result != 0 && errno == EINTR);
    return result;
}
__attribute__((used)) static const struct { const void *replacement; const void *original; }
interpose_usleep __attribute__((section("__DATA,__interpose"))) = {(const void *)delayed_usleep, (const void *)usleep};
