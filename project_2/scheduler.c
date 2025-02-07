#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scheduler.h"
#include "cpu.h"
#include "task.h"

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

void schedule_fcfs(Task* head)
{
    printf("fcfs\n");
}

void schedule_sjf(Task* head)
{
    printf("sjf\n");
}

void schedule_priority(Task* head)
{
    printf("priority\n");
}

void schedule_rr(Task* head)
{
    printf("round robin\n");
}

Task* create_task(int id, int burst, int priority)
{
    //PLACEHOLDER TO GET EVERYTHING TO COMPILE
    Task* t = (Task*)malloc(sizeof(Task));

    t->tid = id;
    t->priority = priority;
    t->burst = burst;
    t->original_burst = 0; // IDRK what this should be yet
    t->waiting_time = 0;
    t->turnaround_time = 0; // IDRK what this should be yet to start...
    t->response_time = -1; // maybe a -1 to indicate it hasn't had a chance to run yet
    t->completed = 0; //not completed
    t->next = NULL;
    
    return t;
}