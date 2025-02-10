#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scheduler.h"
#include "cpu.h"
#include "task.h"
#include "queue.h"

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

Task* findMaxBurst(Task* head, int lastmax)
{
    Task* curr = head;
    Task* max = NULL;
    while(curr != NULL)
    {
        if((max != NULL && curr->burst < lastmax && curr->burst > max->burst) || (max == NULL && curr->burst < lastmax))
        {
            max = curr;
        }
        curr = curr->next;
    }
    return max;
}

Task* sortSJF(Task* head)
{
    int lastmax = 1000;
    Task* sorted = NULL;
    Task* max = NULL;
    while(1)
    {
        max = findMaxBurst(head, lastmax);
        if(max == NULL){break;}
        lastmax = max->burst;

        if(head == max)
        {
            head = head->next;
        }
        else
        {
            Task* prev = head;
            while(prev->next != max)
            {
                prev = prev->next;
            }
            prev->next = max->next;
        }
        max->next = sorted;
        sorted = max;
    }
    return sorted;
}

Task* findMaxPriority(Task* head, int lastmax)
{
    Task* curr = head;
    Task* max = NULL;
    while(curr != NULL)
    {
        if((max != NULL && curr->priority < lastmax && curr->priority> max->priority) || (max == NULL && curr->priority < lastmax))
        {
            max = curr;
        }
        curr = curr->next;
    }
    return max;
}

Task* sortPriority(Task* head)
{
    int lastmax = 1000;
    Task* sorted = NULL;
    Task* max = NULL;
    while(1)
    {
        max = findMaxPriority(head, lastmax);
        if(max == NULL){break;}
        lastmax = max->priority;

        if(head == max)
        {
            head = head->next;
        }
        else
        {
            Task* prev = head;
            while(prev->next != max)
            {
                prev = prev->next;
            }
            prev->next = max->next;
        }
        max->next = sorted;
        sorted = max;
    }
    return sorted;
}

/*
 * response time: Tfirstrun - Tarrival(=0)
 * TAT: Tcompleted - Tarrival
 * wait time: TAT - Tburst
 */
/* process in order of list */
void schedule_fcfs(Task* head)
{
    printf("Scheduling with FCFS\n");
    int time = 0;
    // int arrival = 0;

    Task *curr = head;

    while (curr != NULL) {
        curr->response_time = time;
        curr->waiting_time = time;
        run(curr, curr->burst);

        time = time + curr->burst;
        curr->turnaround_time = time;
        curr->completed = 1;

        curr = curr->next;
    }
}

Task* schedule_sjf(Task* head)
{
    printf("Scheduling with SJF\n");
    Task *sortedHead = sortSJF(head);
    Task* curr = sortedHead;
    int time = 0;

    while(curr != NULL)
    {
        curr->response_time = time;
        curr->waiting_time = time;
        run(curr, curr->burst);

        time = time + curr->burst;
        curr->turnaround_time = time;
        curr-> completed = 1;

        curr = curr->next;
    }
    return sortedHead;
}

Task* schedule_priority(Task* head)
{
    printf("Scheduling with Strict Priority\n");
    Task *sortedHead = sortPriority(head);
    Task* curr = sortedHead;
    int time = 0;

    while(curr != NULL)
    {
        curr->response_time = time;
        curr->waiting_time = time;
        run(curr, curr->burst);

        time = time + curr->burst;
        curr->turnaround_time = time;
        curr-> completed = 1;

        curr = curr->next;
    }
    return sortedHead;
}

void schedule_rr(Task* head)
{
    /*
    1. implement queue (array?), queue processes
    2. until queue empty,
        a. pop front of queue
        b. if remaining burst > time
            i. run(10), time+= 10, burst -= 10, requeue
           else: run(burst), time += burst, burst = 0, completed = 1
    */
    Task* curr = head;
    Task* front;
    Queue q;
    q.front = 0;
    q.back = 0;
    int time = 0;

    printf("Scheduling with Round Robin\n");

    while (curr != NULL) 
    {
        enqueue(&q, curr);
        curr = curr->next;
    }
    //printQueue(&q);

    while(!(isEmpty(&q)))
    {
        front = q.items[q.front];
        //printf("BURST TIME: %d, TASK ID: %d, FRONT: %d, BACK: %d\n", front->burst, front->tid, q.front, q.back);
        dequeue(&q);
        if(front->response_time == -1)
        {
            front->response_time = time;
        }
        if(front->burst > TIME_QUANTUM)
        {
            run(front, TIME_QUANTUM);
            front->burst -= TIME_QUANTUM;
            time += TIME_QUANTUM;
            //front->waiting_time += time;
            enqueue(&q, front);
        }
        else if (front->completed == 0)
        {
            //front->waiting_time += time;
            run(front, front->burst);
            time += front->burst;
            front->burst -= front->burst;
            front->waiting_time = time;
            front->turnaround_time = time;
            front->waiting_time -= front->original_burst;
            front->completed = 1;
        }
    }
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
    t->response_time = -1; // maybe a -1 to indicate it hasn't had a chance to run yet
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
        printf("  Completed: %d\n", curr->completed);
        printf("-------------------------\n");
        curr = curr->next;
    }
}