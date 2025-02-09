#include <stdio.h>
#include <stdlib.h>
#include "scheduler.h"

void free_tasks(Task* head);
void print_stats(Task* head);

/* DRIVER LOGIC
 * check command-line args
 * read_tasks_from_file() -> get list of tasks 
 * select scheduling alg based on argument
 * print_stats()
 * free_tasks() to free allocated memory 
 */

int main(int argc, char *argv[]) {
    int algo;
    if (argc != 3) {
        printf("Usage: %s <filename> <algorithm>\n", argv[0]);
        printf("Algorithms: 1=FCFS, 2=SJF, 3=Priority, 4=RR\n");
        return 1;
    }

    Task* tasks = read_tasks_from_file(argv[1]);
    // print_list(tasks);
    
    algo = atoi(argv[2]);
    switch (algo) {
    case 1:
        schedule_fcfs(tasks);
        break;
    case 2:
        schedule_sjf(tasks);
        break;
    case 3:
        schedule_priority(tasks);
        break;
    case 4:
        schedule_rr(tasks);
        break;
    default:
        printf("Incorrect algorithm choice.\n");
        printf("Usage: %s <filename> <algorithm>\n", argv[0]);
        printf("Algorithms: 1=FCFS, 2=SJF, 3=Priority, 4=RR\n");
        return 1;
    }

    print_stats(tasks);
    free_tasks(tasks);
    
    return 0;
}

void print_stats(Task* head) {
    Task* current;
    float avg_waiting = 0;
    float avg_turnaround = 0;
    float avg_response = 0;
    int count = 0;
    
    printf("\nTask Statistics:\n");
    printf("ID\tWT\tTAT\tRT\n");
    
    current = head;
    while (current != NULL) {
        printf("%d\t%d\t%d\t%d\n",
               current->tid,
               current->waiting_time,
               current->turnaround_time,
               current->response_time);
        
        avg_waiting += current->waiting_time;
        avg_turnaround += current->turnaround_time;
        avg_response += current->response_time;
        count++;
        current = current->next;
    }
    
    if (count > 0) {
        printf("\nAverages:\n");
        printf("Waiting Time: %.2f\n", avg_waiting/count);
        printf("Turnaround Time: %.2f\n", avg_turnaround/count);
        printf("Response Time: %.2f\n", avg_response/count);
    }
}

void free_tasks(Task* head)
{
    Task *curr = head;
    Task *next;

    while (curr != NULL) {
        next = curr->next;
        free(curr);
        curr = next;
    }
}