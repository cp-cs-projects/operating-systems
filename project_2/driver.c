#include <stdio.h>
#include <stdlib.h>
#include "scheduler.h"

void add_task(Task** head, Task* task);
void free_tasks(Task* head);
void print_stats(Task* head);

int main(int argc, char *argv[]) {
    
    if (argc != 3) {
        printf("Usage: %s <filename> <algorithm>\n", argv[0]);
        printf("Algorithms: 1=FCFS, 2=SJF, 3=Priority, 4=RR\n");
        return 1;
    }
    
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