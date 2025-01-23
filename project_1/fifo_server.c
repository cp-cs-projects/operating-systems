#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#define SIZE 2
// start server first

int main(void)
{
    int fifo;
    char buffer[SIZE];
    char input[SIZE];
    const char *FIFO = "/tmp/MY_FIFO";

    /* Create the FIFO or die trying */
    assert(mkfifo(FIFO, S_IRUSR | S_IWUSR) == 0);

    /* Try to open the FIFO. Delete FIFO if open() fails */
    fifo = open(FIFO, O_RDONLY);
    if (fifo == -1)
    {
        fprintf(stderr, "Failed to open FIFO\n");
        unlink(FIFO);
        return 1;
    }

    /* Input character processing */
    ssize_t bytes_read = read(fifo, &input, 1);
    printf("%c -> ", input[0]);
    bytes_read = read(fifo, &buffer, 1);
    printf("%c\n", buffer[0]);

    while (bytes_read)
    {
        printf("%c -> ", buffer[0]);         // Print current character
        bytes_read = read(fifo, &buffer, 1); // Read next character
        printf("%c\n", buffer[0]);
        if (buffer[0] == input[0])
            break;
    }
    /* Read a 0 from the FIFO, so close and delete the FIFO */
    close(fifo);
    unlink(FIFO);

    return 0;
}