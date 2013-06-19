// test utility to call malloc repeatedly

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const int PAGE_SIZE = 4 * 1024;

int main(int argc, char** argv) {
    long startup = 2;
    long bytes = 1024;
    int secs = 1;

    // never use malloc, we're looking for brk calls
    if (!mallopt(M_MMAP_THRESHOLD, bytes*2))
	perror("mallopt failed");

    if (argc > 1)
        bytes = atol(argv[1]);
    if (argc > 2)
        secs = atoi(argv[1]);

    pid_t pid = getpid();

    FILE* f;
    if ((f = fopen("/proc/self/statm", "r")) == NULL) {
        perror("couldn't read /proc/self/statm");
        return -1;
    }

    long pages;
    if (fscanf(f, "%*d %*d %*d %*d %*d %ld\n", &pages))
	fprintf(stderr, "[%d] brk=%p data=%ld\n", pid, sbrk(0), pages * PAGE_SIZE);

    sleep(startup);

    long total = 0;
    for (;;) {
        fprintf(stderr, "[%d] ", pid);
        void* p;
        if ((p = malloc(bytes)) == NULL) {
            fprintf(stderr, "malloc failed");
        }
        else {
            total += bytes;
            fprintf(stderr, "malloc %ld @ %p", bytes, p);
        }

        fprintf(stderr, ", total=%ld", total);
        fprintf(stderr, ", brk=%p", sbrk(0));

        rewind(f);
        if (fscanf(f, "%*d %*d %*d %*d %*d %ld\n", &pages))
            fprintf(stderr, ", data=%ld\n", pages * PAGE_SIZE);

        sleep(secs);
    }

    return 0;
}
