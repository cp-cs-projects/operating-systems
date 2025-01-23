all: anon_pipe named_pipe



fork_vals: fork_vals.c
 gcc -Wall -Werror -g -o $@ $?



fork_timing: fork_timing.c
 gcc -Wall -Werror -g -o $@ $?

clean:
 -rm -rf fork_vals fork_timing