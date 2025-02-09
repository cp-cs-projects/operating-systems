#ifndef TASK_H
#define TASK_H

/*
defines struct for a job in the simulator
create_task() called when reading tasks from schedule.txt
*/

struct task {
    int tid;              /* Task ID */
    int priority;         /* Priority level */
    int burst;            /* Remaining burst time */
    int original_burst;   /* Initial burst time */
    int waiting_time;     /* Total waiting time */
    int turnaround_time;  /* Total turnaround time */
    int response_time;    /* Response time */
    int completed;        /* Completion flag */
    struct task *next;    /* Next task in list */
};
 
typedef struct task Task;

/* Task management functions */
Task* create_task(int id, int burst, int priority);

void add_task(Task** head, Task* task);
#endif
