#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#define SIZE 2
// start client after server

void getNextAlphabet(char *alp)
{
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
    // pid_t pid;
    int i;
    char buffer[SIZE];
    const char *FIFO = "/tmp/MY_FIFO";
    int fifo;

    /* Prompt and read initial character */
    printf("Enter a character: ");
    fgets(buffer, SIZE, stdin);
    fifo = open(FIFO, O_WRONLY);
    assert(fifo != -1);
    write(fifo, &buffer[0], 1); // write first char
    for (i = 0; i < 52; ++i)
    {
        /* Use the file name to open the FIFO for writing */
        getNextAlphabet(&buffer[0]);
        write(fifo, buffer, 1);
    }

    close(fifo);
    return 0;
}