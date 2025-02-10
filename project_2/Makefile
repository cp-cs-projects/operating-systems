all: scheduler

scheduler: scheduler.c cpu.c driver.c queue.c
	gcc -Wall -Werror -g -o $@ $?
 
clean:
	-rm -rf scheduler