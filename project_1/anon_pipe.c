#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define SIZE 2

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

int main(int argc, const char *argv[]) {
    pid_t pid;
    int i;
    char buffer[SIZE];
    int pipefd[2];

    /* Prompt and read initial character */
	printf("Enter a character: ");
    fgets(buffer, SIZE, stdin);


    for (i = 0; i < 52; ++i) {

        if (pipe(pipefd) < 0) {
            printf("ERROR: Failed to open pipe\n");
            exit(1);
        }

        pid = fork();
        
        if (pid == -1) {
            perror("fork");
            exit(1);
        }

        if (pid == 0) {  

            getNextAlphabet(&buffer[0]);

            //close the read end
            close(pipefd[0]);
            
            /* Write modified character to parent */
            write(pipefd[1], buffer, 1);

            //we're done so now close the write end
            close(pipefd[0]);
            exit(0);
        } 
        else {  
            int status = 0;
            waitpid(pid, &status, WUNTRACED);

            /* Print current character */
            printf("%c -> ", buffer[0]);

            // close the write end
            close(pipefd[1]);

            /* Read modified character from child */
            read(pipefd[0], buffer, 1);
            
            /* Print new character */ 
            printf("%c\n", buffer[0]);
            
            // Wait for child to finish
            wait(NULL);
        }
    }
    
    return 0;
}