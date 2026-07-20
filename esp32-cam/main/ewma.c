#include "ewma.h"
#include <math.h>
#include <stdbool.h>

void ewma_init(ewma_t *filter, float alpha) {
    filter->alpha = alpha;
    filter->current_avg = 0.0;
    filter->is_initialized = false;
}

float ewma_update(ewma_t *filter, float next_value) {
    if (!filter->is_initialized) {
        filter->current_avg = next_value;
        filter->is_initialized = true;
    } else {
        // Standard EWMA formula: S_t = alpha * Y_t + (1 - alpha) * S_{t-1}
        filter->current_avg = (filter->alpha * next_value) + ((1.0f - filter->alpha) * filter->current_avg);
    }
    return filter->current_avg;
}

float ewma_get_deviation_pct(ewma_t *filter, float current_value) {
    if (!filter->is_initialized || filter->current_avg == 0.0f) {
        return 0.0f;
    }
    // Calculate the relative absolute deviation
    float diff = fabsf(current_value - filter->current_avg);
    return (diff / filter->current_avg) * 100.0f;
}