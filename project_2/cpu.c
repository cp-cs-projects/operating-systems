#include <stdio.h>
#include "cpu.h"

void run(Task *task, int slice) {
    printf("Running task [%d] for %d units\n", task->tid, slice);
}