#include <stdbool.h>
#include <stdio.h>
#include "queue.h"


bool isEmpty(Queue* q) { return (q->front == q->back - 1); }

void enqueue(Queue* q, Task* t)
{
    q->items[q->back] = t;
    q->back++;
}

void dequeue(Queue* q)
{
    if (isEmpty(q)) {
        printf("Queue is empty\n");
        return;
    }
    q->front++; // moving front one back
}

// Function to print the current queue
void printQueue(Queue* q)
{
    printf("QUEUE: ");
    for (int i = q->front + 1; i < q->back; i++) {
        Task* task = q->items[i]; // Access Task pointer
        printf("[Id: %d, Priority: %d, Burst: %d] ", task->tid, task->priority, task->burst);
    }
    printf("\n");
}

// int main()
// {
//     Queue q;
//     q.front = -1;
//     q.back = 0;
    
//     // Enqueue elements
//     enqueue(&q, head);
//     printQueue(&q);

//     enqueue(&q, 20);
//     printQueue(&q);

//     enqueue(&q, 30);
//     printQueue(&q);

//     // Dequeue an element
//     dequeue(&q);
//     printQueue(&q);

//     return 0;
// }
