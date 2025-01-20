#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>
#include <stdint.h>

#define LOG(msg, ...) \
    do { \
        printf("File %s | Line %d :: ", __FILE__, __LINE__); \
        printf((msg), ##__VA_ARGS__); \
    } while (0)

static const int FORKSRV_FD = 198;

typedef uint8_t u8;
typedef int32_t s32;
typedef uint32_t u32;

#define SHM_ENV_VAR "__AFL_SHM_ID"
#define MAP_SIZE 65536
#define EXEC_FAIL_SIG 0xfee1dead

static u8 *trace_bits;
static s32 shm_id;
static s32 forksrv_pid, child_pid = -1;
static s32 fsrv_ctl_fd, fsrv_st_fd;
static int kill_signal = 0; // Global variable to store exit status

static void remove_shm(void) {
    shmctl(shm_id, IPC_RMID, NULL);
}

static void setup_shm(void) {
    char *shm_str;
    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (shm_id < 0) {
        perror("shmget failed");
        exit(EXIT_FAILURE);
    }

    atexit(remove_shm);
    shm_str = malloc(10);
    snprintf(shm_str, 10, "%d", shm_id);
    setenv(SHM_ENV_VAR, shm_str, 1);
    free(shm_str);

    trace_bits = shmat(shm_id, NULL, 0);
    if (trace_bits == (void *)-1) {
        perror("shmat failed");
        exit(EXIT_FAILURE);
    }
}

static void init_forkserver(char **argv) {
    struct itimerval it;
    int st_pipe[2], ctl_pipe[2];
    int status;
    s32 rlen;

    if (pipe(st_pipe) || pipe(ctl_pipe)) {
        perror("pipe() failed");
        exit(EXIT_FAILURE);
    }

    forksrv_pid = fork();
    if (forksrv_pid < 0) {
        perror("fork() failed");
        exit(EXIT_FAILURE);
    }

    if (!forksrv_pid) {
        struct rlimit r = {0, 0};
        setrlimit(RLIMIT_CORE, &r);

        setsid();
        dup2(ctl_pipe[0], FORKSRV_FD);
        dup2(st_pipe[1], FORKSRV_FD + 1);

        close(ctl_pipe[0]);
        close(ctl_pipe[1]);
        close(st_pipe[0]);
        close(st_pipe[1]);

        execv(argv[0], argv);
        *(u32 *)trace_bits = EXEC_FAIL_SIG;
        exit(0);
    }

    close(ctl_pipe[0]);
    close(st_pipe[1]);

    fsrv_ctl_fd = ctl_pipe[1];
    fsrv_st_fd = st_pipe[0];

    it.it_value.tv_sec = 5;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);

    rlen = read(fsrv_st_fd, &status, 4);
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);

    if (rlen != 4) {
        perror("forkserver handshake failed");
        exit(EXIT_FAILURE);
    }

    LOG("forkserver handshake successful\n");
}

static void run_target(char **argv) {
    struct itimerval it;
    int status;

    memset(trace_bits, 0, MAP_SIZE);
    write(fsrv_ctl_fd, &status, 4);
    read(fsrv_st_fd, &status, 4);

    it.it_value.tv_sec = 1;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);

    read(fsrv_st_fd, &status, 4);

    if (WIFSIGNALED(status)) {
        kill_signal = WTERMSIG(status);
    } else {
        kill_signal = 0;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [args...]\n", argv[0]);
        return 1;
    }

    setup_shm();
    init_forkserver(argv + 1);

    while (1) {
        memset(trace_bits, 0, MAP_SIZE);
        run_target(argv);

        if (kill_signal != 0) {
            printf("The child exited with something other than 0!\n");
            break;
        }
    }

    return 0;
}