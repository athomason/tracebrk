// test utility to call sbrk/malloc repeatedly

#define USE_MALLOC 1
#define USE_SBRK 0

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const int PAGE_SIZE = 4 * 1024;

static inline long data_size() {
    FILE* f;
    if ((f = fopen("/proc/self/statm", "r")) == NULL) {
        perror("couldn't read /proc/self/statm");
        return -1;
    }

    long pages;
    if (fscanf(f, "%*d %*d %*d %*d %*d %ld\n", &pages))
        return pages * PAGE_SIZE;
    fclose(f);
    return 0;
}

int main(int argc, char** argv) {
    long startup = 2;
    long bytes = 1024;
    int secs = 1;

    if (argc > 1)
        bytes = atol(argv[1]);
    if (argc > 2)
        secs = atoi(argv[1]);

    // always want brk allocations
    mallopt(M_MMAP_THRESHOLD, bytes << 2);

    pid_t pid = getpid();

    fprintf(stderr, "[%d] brk=%p data=%ld\n", pid, sbrk(0), data_size());

    sleep(startup);

    long total = 0;
    for (;;) {
        fprintf(stderr, "[%d]", pid);
        #if USE_MALLOC
        void* p;
        if (!(p = malloc(bytes))) {
            fprintf(stderr, " malloc(failed),");
        }
        else {
            total += bytes;
            fprintf(stderr, " malloc(%ld)@%p,", bytes, p);
        }
        #endif
        #if USE_SBRK
        if (!sbrk(bytes)) {
            fprintf(stderr, " sbrk(failed),");
        }
        else {
            total += bytes;
            fprintf(stderr, " sbrk(%ld),", bytes);
        }
        #endif

        fprintf(stderr, " total=%ld", total);
        fprintf(stderr, " brk=%p", sbrk(0));
        fprintf(stderr, " data=%ld", data_size());
        fprintf(stderr, "\n");

        sleep(secs);
    }

    return 0;
}
