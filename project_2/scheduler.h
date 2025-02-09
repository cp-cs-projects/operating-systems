#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "task.h"

#define TIME_QUANTUM 10

/* Core scheduling algorithms */
void schedule_fcfs(Task* head);
void schedule_sjf(Task* head);
void schedule_priority(Task* head);
void schedule_rr(Task* head);

/* File input functions */
Task* read_tasks_from_file(const char* filename);
void parse_line(char* line, int* tid, int* priority, int* burst);

/* useful to run more than one simulation on same task set */
void reset_tasks(Task* head);

// debugging
void print_list(Task* head);
#endif