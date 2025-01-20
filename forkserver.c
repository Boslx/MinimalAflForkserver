#include <sys/shm.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LOG(msg, ...) \
    do { \
        printf("File %s | Line %d :: ", __FILE__, __LINE__); \
        printf((msg), ##__VA_ARGS__); \
    } while (0)

static const char* SHM_ENV_VAR = "__AFL_SHM_ID";
static const int FORKSRV_FD = 198;
static unsigned char *afl_area = NULL;

static void afl_trace(unsigned int cur_location) {
    static int prev_location = 0;

    int offset = cur_location ^ prev_location;
    if (afl_area) {
        afl_area[offset] += 1;
    }

    prev_location = cur_location >> 1;
}

static void init_forkserver(void) {
    LOG("Initializing forkserver with fd=%d\n", FORKSRV_FD);

    int ret = write(FORKSRV_FD + 1, "\0\0\0\0", 4);
    if (ret != 4) {
        perror("Couldn't write to forksrv");
        exit(EXIT_FAILURE);
    }

    LOG("Successfully wrote nulls to forksrv, ret=%d\n", ret);
}

static void forkserver_read(void) {
    unsigned int value;
    int ret = read(FORKSRV_FD, &value, 4);

    LOG("Read from forksrv value=%d, ret=%d\n", value, ret);

    if (ret != 4) {
        perror("Couldn't read from forksrv");
        exit(EXIT_FAILURE);
    }
}

static void forkserver_write(unsigned int value) {
    int ret = write(FORKSRV_FD + 1, &value, 4);

    LOG("Wrote to forksrv value=%d, ret=%d\n", value, ret);

    if (ret != 4) {
        perror("Couldn't write to forksrv");
        exit(EXIT_FAILURE);
    }
}

static void init_shm(void) {
    LOG("Initializing SHM\n");

    const char *afl_shm_id_str = getenv(SHM_ENV_VAR);
    if (!afl_shm_id_str) {
        perror("No AFL SHM segment specified. AFL's SHM env var is not set.\n");
        exit(EXIT_FAILURE);
    }

    int afl_shm_id = atoi(afl_shm_id_str);
    afl_area = shmat(afl_shm_id, NULL, 0);
    if (afl_area == (void*) -1) {
        perror("Couldn't map shm segment");
        exit(EXIT_FAILURE);
    }

    LOG("afl_area mapped at %p\n", (void*)afl_area);
}

static void close_forksrv_fds(void) {
    close(FORKSRV_FD);
    close(FORKSRV_FD + 1);
}

static void bail(void) {
    LOG("Exiting forkserver\n");
    _exit(0);
}

static void dummy_testcase(void) {
    LOG("Executing dummy_testcase()");
}

static void spawn_child(void) {
    while (1) {
        forkserver_read();

        pid_t child_pid = fork();

        if (child_pid == 0) {
            // Child process
            dummy_testcase();
            exit(0);
        } else if (child_pid > 0) {
            // Parent process
            forkserver_write(child_pid);

            int status;
            waitpid(child_pid, &status, 0);

            int report_status = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            forkserver_write(report_status);
        } else {
            perror("Fork failed");
            exit(EXIT_FAILURE);
        }
    }
}

int main(void) {
    init_shm();
    init_forkserver();
    spawn_child();
    close_forksrv_fds();

    return 0;
}