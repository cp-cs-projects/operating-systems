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

/* process in order of list */
void schedule_fcfs(Task* head)
{
    int time = 0;

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
    t->original_burst = burst; // storing original burst to use later
    t->waiting_time = 0;
    t->turnaround_time = 0; // IDRK what this should be yet to start...
    t->response_time = 0; // maybe a -1 to indicate it hasn't had a chance to run yet
    t->completed = 0; //not completed
    t->next = NULL;
    
    return t;
}
void add_task(Task **head, Task *task) {
    Task *curr = *head;

    /* traverse to find last node */
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = task;
}

/* opens scheduler.txt, 
for each line: call parse_line(), create_task(), add_task() to list
return head of linked list */
Task* read_tasks_from_file(const char* filename)
{
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file");
        exit(1);
    }

    char buf[50];
    Task *head = NULL; /*init lst*/

    while (fgets(buf, sizeof(buf), file) != NULL) {
        int tid, priority, burst;
        parse_line(buf, &tid, &priority, &burst);
        
        Task* task = create_task(tid, burst, priority);
        
        if (head == NULL) {
            head = task; 
        } else {
            add_task(&head, task);
        }
    }

    fclose(file);
    return head;
}

void reset_tasks(Task* head);

void print_list(Task* head) {
    Task *curr = head;
    while (curr != NULL) {
        printf("Task ID: %d\n", curr->tid);
        printf("  Priority: %d\n", curr->priority);
        printf("  Burst: %d\n", curr->burst);
        printf("  Original Burst: %d\n", curr->original_burst);
        printf("  Waiting Time: %d\n", curr->waiting_time);
        printf("  Turnaround Time: %d\n", curr->turnaround_time);
        printf("  Response Time: %d\n", curr->response_time);
        printf("  Completed: %s\n", curr->completed ? "Yes" : "No");
        printf("-------------------------\n");
        curr = curr->next;
    }
}