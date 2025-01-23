#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>

#define SHM_SIZE 1024
#define SHM_KEY 12345
#define SIZE 2

struct shared_data
{
    char buffer[SIZE];
    int ready; /* Flag to indicate message is ready */
};

void getNextAlphabet(char* alp) {
    char *next = (char *)calloc(2, sizeof(char));
    next[1] = '\0';
    
    if (*alp == 'Z')
        next[0] = 'a';
    else if (*alp == 'z')
        next[0] = 'A';
    else
        next[0] = *alp + 1;
        
    *alp = *next;
    free(next);
}

int main(int argc, const char *argv[])
{
    int shm_id;
    struct shared_data *shared_mem;
    pid_t child_pid;

    /* Create shared memory segment */
    shm_id = shmget(SHM_KEY, SHM_SIZE, IPC_CREAT | 0666);
    if (shm_id == -1)
    {
        perror("shmget");
        exit(1);
    }

    /* Attach shared memory segment */
    shared_mem = (struct shared_data *)shmat(shm_id, NULL, 0);
    if (shared_mem == (struct shared_data *)-1)
    {
        perror("shmat");
        exit(1);
    }

    /* Initialize shared memory */
    memset(shared_mem->buffer, 0, sizeof(shared_mem->buffer ));
    shared_mem->ready = 0;

    /* Create child process */
    child_pid = fork();
    assert(child_pid >= 0);

    if (child_pid == 0)
    {
        /* Child process */

        /* Child sends message */
        strncpy(shared_mem->buffer, "h", sizeof(shared_mem->buffer));
        printf("Child is sending: '%s'\n", shared_mem->buffer);
        shared_mem->ready = 1; /* Signal that message is ready */

        /* Detach shared memory */
        shmdt(shared_mem);

        exit(0);
    }

    /* Parent process */

    /* Wait for child's message */
    while (!shared_mem->ready)
        usleep(1000); /* Small delay to prevent busy waiting */

    printf("Parent received: '%s'\n", shared_mem->buffer);

    /* Wait for child to complete */
    wait(NULL);

    printf("Parent has received and printed the message\n");

    /* Cleanup shared memory */
    shmdt(shared_mem);
    shmctl(shm_id, IPC_RMID, NULL);

    return 0;
}