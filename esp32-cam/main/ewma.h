#ifndef EWMA_H
#define EWMA_H

#include <stdbool.h>

typedef struct {
    float alpha;         // Smoothing factor (0 < alpha <= 1), typically chosen as 0.2
    float current_avg;   // Current moving average value
    bool is_initialized; // Mark the first receipt of data
} ewma_t;

// Initialize a new EWMA instance
void ewma_init(ewma_t *filter, float alpha);

// Update the filter with a new value and return the filtered average
float ewma_update(ewma_t *filter, float next_value);

// Calculate the percentage deviation between the current value and the moving average
float ewma_get_deviation_pct(ewma_t *filter, float current_value);

#endif // EWMA_H