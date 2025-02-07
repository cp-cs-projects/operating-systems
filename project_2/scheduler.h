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

/* Helper functions */
void reset_tasks(Task* head);

#endif