#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scheduler.h"
#include "cpu.h"

void parse_line(char* line, int* tid, int* priority, int* burst) {
    char* token;
    char* rest = line;
    
    /* Parse TID (remove 'T' prefix) */
    token = strsep(&rest, ",");
    *tid = atoi(token + 1);
    
    /* Parse priority */
    token = strsep(&rest, ",");
    *priority = atoi(token);
    
    /* Parse burst */
    token = strsep(&rest, ",");
    *burst = atoi(token);
}