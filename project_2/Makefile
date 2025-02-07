all: scheduler

scheduler: scheduler.c cpu.c driver.c
	gcc -Wall -Werror -g -o $@ $?
 
clean:
	-rm -rf scheduler