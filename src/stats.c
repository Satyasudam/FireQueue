#include "../include/stats.h"
#include <stdio.h>

static int allowed_count = 0;
static int dropped_count = 0;

void stats_inc_allowed() { allowed_count++; }
void stats_inc_dropped() { dropped_count++; }

void stats_print() {
    printf("Allowed: %d | Dropped: %d\n",
        allowed_count, dropped_count);
}
