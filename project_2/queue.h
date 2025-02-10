#ifndef QUEUE_H
#define QUEUE_H

#define SIZE 50
#include "task.h"

typedef struct {
    Task* items[SIZE];
    int front, back;
} Queue;

void enqueue(Queue* q, Task* t);

void dequeue(Queue* q);

void printQueue(Queue* q);

#endif