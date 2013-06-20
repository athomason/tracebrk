#include <errno.h>
#include <getopt.h>
#include <libunwind-ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined __x86_64__
    // http://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
    #define SYSCALL_ARG1        rdi
    #define SYSCALL_ARG2        rsi
    #define SYSCALL_ARG3        rdx
    #define SYSCALL_ARG4        r10
    #define SYSCALL_ARG5        r8
    #define SYSCALL_ARG6        r9
    #define SYSCALL_NUM_OFFSET  (8*ORIG_RAX)
    #define SYSCALL_RET_OFFSET  (8*RAX)
#else
    #error Only x86_64 supported.
#endif

#define USAGE()    do { FATAL("usage: %s [-e <exe>] [-p <pid>] [-c] [-q]\n", argv[0]); } while (0)
#define WARN(...)  do { fprintf(stderr, __VA_ARGS__); } while (0)
#define FATAL(...) do { fprintf(stderr, __VA_ARGS__); return EXIT_FAILURE; } while (0)
#define PANIC(...) do { fprintf(stderr, __VA_ARGS__); goto CLEANUP; } while (0)
#define ERRSTR     (strerror(errno))

#define DEBUG 0

extern char **environ;

int stopped = 0;
void handler(int sig) {
    if (sig == SIGINT)
        if (stopped++)
            _exit(-1);
}

int
main(int argc, char** argv)
{
    if (argc < 2)
        USAGE();

    int trace_mmap = 0;
    int quiet = 0;
    pid_t pid = 0;
    const char* binary = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "e:p:mqh")) != -1) {
        if (opt == 'e')
            binary = strdup(optarg);
        else if (opt == 'p') {
            if ((pid = atoi(optarg)) == 0)
                FATAL("bad pid '%s'\n", optarg);
            if (kill(pid, 0) < 0)
                FATAL("couldn't signal process %d: %s\n", pid, ERRSTR);
        }
        else if (opt == 'm')
            trace_mmap++;
        else if (opt == 'q')
            quiet++;
        else if (opt == 'h')
            USAGE();
    }

    if (!binary && !pid)
        FATAL("either -e or -p is required\n");

    int started = 0;
    if (pid) {
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
            FATAL("PTRACE_ATTACH failed: %s\n", ERRSTR);
    }
    else {
        pid = fork();
        if (pid < 0)
            FATAL("fork failed: %s\n", ERRSTR);
        else if (pid == 0) {
            if (quiet) {
                close(1); // stdout
                close(2); // stderr
            }

            ptrace(PTRACE_TRACEME, NULL, NULL, NULL);

            char** args = calloc(argc - optind + 1, sizeof(char*));
            args[0] = (char*) binary;
            int i;
            for (i = 0; optind < argc; optind++, i++)
                args[i] = argv[optind];

            execve(binary, args, environ);
            FATAL("exec of %s failed: %s\n", binary, ERRSTR);
        }
        started = 1;
    }

    struct UPT_info* ui = _UPT_create(pid);
    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!as)
        FATAL("unw_create_addr_space() failed");
    unw_set_caching_policy(as, UNW_CACHE_GLOBAL);

    signal(SIGINT, handler);

    int entering; // go through loop twice per syscall, once on entry and again on exit
    void* last_brk = NULL;
    for (entering = 0; !stopped; entering = !entering) {
        int status;
        if (waitpid(-1, &status, 0) < 0) {
            if (errno == EINTR)
                continue;
            PANIC("waitpid() failed: %s\n", ERRSTR);
        }

        #if DEBUG
        fprintf(stderr, "entering=%d exited=%d signaled=%d stopped=%d sig=%d\n",
                entering, WIFEXITED(status), WIFSIGNALED(status),
                WIFSTOPPED(status), WSTOPSIG(status));
        #endif

        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        int pending_sig = 0, show_backtrace = 0;
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGSTOP)
                entering = 0;
            else if (sig == SIGKILL)
                break;
            else if (sig != SIGTRAP)
                pending_sig = sig;
            else if (!entering) { // SIGTRAP
                long syscall, retval;
                struct user_regs_struct regs;
                syscall = ptrace(PTRACE_PEEKUSER, pid, SYSCALL_NUM_OFFSET, NULL);
                retval = ptrace(PTRACE_PEEKUSER, pid, SYSCALL_RET_OFFSET, NULL);
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);

                #if DEBUG
                fprintf(stderr, "  syscall=%ld retval=%ld\n", syscall, retval);
                #endif

                if (syscall == SYS_brk) {
                    void* new_brk = (void*) retval;
                    if (last_brk == NULL)
                        printf("brk is at %p\n", new_brk);
                    else if (new_brk == last_brk)
                        printf("brk unchanged at %p\n", new_brk);
                    else
                        printf("brk moved %ld bytes to %p\n",
                                new_brk - last_brk, new_brk);
                    last_brk = new_brk;
                    show_backtrace++;
                }
                else if (trace_mmap && syscall == SYS_mmap) {
                    void* addr = (void*) retval;
                    int len = (int) regs.SYSCALL_ARG2;
                    int prot = (int) regs.SYSCALL_ARG3;
                    int flags = (int) regs.SYSCALL_ARG4;
                    if (prot & PROT_READ && prot & PROT_WRITE &&
                        flags & MAP_PRIVATE && flags & MAP_ANONYMOUS
                    ) {
                        show_backtrace++;
                        printf("new anonymous map of %d bytes at %p\n", len, addr);
                    }
                }
            }
        }

        if (show_backtrace) {
            unw_word_t ip, sp, start_ip = 0;
            int n = 0, ret;
            unw_cursor_t c;
            char buf[512];

            ret = unw_init_remote(&c, as, ui);
            if (ret < 0)
                PANIC("unw_init_remote() failed: ret=%d\n", ret);
            do {
                if ((ret = unw_get_reg(&c, UNW_REG_IP, &ip)) < 0
                        || (ret = unw_get_reg(&c, UNW_REG_SP, &sp)) < 0)
                    PANIC("unw_get_reg/unw_get_proc_name() failed: ret=%d\n", ret);

                if (n == 0)
                    start_ip = ip;

                buf[0] = '\0';
                unw_get_proc_name(&c, buf, sizeof(buf), NULL);

                // call addr2line for file and line info
                char linenum[256] = "";
                if (binary) {
                    char addr2line[128];
                    snprintf(addr2line, sizeof(addr2line), "addr2line -C -e %s -i %lx", binary, ip);

                    FILE* f = popen(addr2line, "r");
                    if (f == NULL)
                        WARN("popen failed: %s\n", ERRSTR);
                    else {
                        // read just first file:line pair
                        char output[256];
                        if (fgets(output, sizeof(output), f) && output[0] != '?') {
                            // chomp newline while copying
                            char *p, *q;
                            for (p = output, q = linenum; p != 0; p++, q++) {
                                if (*p == '\n') {
                                    *q = '\0';
                                    break;
                                }
                                else {
                                    *q = *p;
                                }
                            }
                        }
                        pclose(f);
                    }
                }

                printf("%016lx %-32s %s\n", (long) ip, buf, linenum);

                ret = unw_step(&c);
                if (ret < 0) {
                    unw_get_reg(&c, UNW_REG_IP, &ip);
                    PANIC("FAILURE: unw_step() returned %d for ip=%lx (start ip=%lx)\n",
                        ret, (long) ip, (long) start_ip);
                }

                if (++n > 64) {
                    /* guard against bad unwind info in old libraries... */
                    PANIC("too deeply nested---assuming bogus unwind (start ip=%lx)\n",
                        (long) start_ip);
                }
            } while (ret > 0);
            printf("\n");
        }

        if (ptrace(PTRACE_SYSCALL, pid, NULL, pending_sig) < 0)
            PANIC("PTRACE_SYSCALL: %s\n", ERRSTR);
    }

    CLEANUP:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    _UPT_destroy (ui);
    unw_destroy_addr_space(as);
    if (started)
        kill(pid, SIGKILL);

    return EXIT_SUCCESS;
}
