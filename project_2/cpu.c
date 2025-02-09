#include <stdio.h>
#include "cpu.h"

/*
simulates CPU executing task for certain time unit
scheduling functions calls run(task, slice) to simulate execution

*/

void run(Task *task, int slice) {
    printf("Running task [%d] for %d units\n", task->tid, slice);
}
