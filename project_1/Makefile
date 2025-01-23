all: anon_pipe fifo_client fifo_server shared_mem

anon_pipe: anon_pipe.c
	gcc -Wall -Werror -g -o $@ $?

fifo_client: fifo_client.c
	gcc -Wall -Werror -g -o $@ $?

fifo_server: fifo_server.c
	gcc -Wall -Werror -g -o $@ $?

shared_mem: shared_mem.c
	gcc -Wall -Werror -g -o $@ $?
 
clean:
	-rm -rf anon_pipe anon_pipe.dSYM fifo_client fifo_client.dSYM fifo_server fifo_server.dSYM shared_mem shared_mem.dSYM