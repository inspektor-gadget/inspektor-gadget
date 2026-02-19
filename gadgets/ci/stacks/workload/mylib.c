#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

void print_hello_world(void) {
    printf("Hello, World!\n");
}

void sleep_one_second(void) {
    sleep(1);
}

void busy_loop_500ms(void) {
    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    long elapsed_ms = 0;
    while (elapsed_ms < 500) {
        clock_gettime(CLOCK_MONOTONIC, &current);
        elapsed_ms = (current.tv_sec - start.tv_sec) * 1000 +
                     (current.tv_nsec - start.tv_nsec) / 1000000;
    }
}

void *allocate_memory(size_t size) {
    printf("Calling malloc.\n");
    return malloc(size);
}
