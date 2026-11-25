package report

import "time"

// Returns the mean given an array of floats.
func Mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	var sum float64
	for _, v := range values {
		sum += v
	}

	return sum / float64(len(values))
}

// Returns the mean of durations, in nanoseconds. Used for lookup times.
func MeanDuration(values []time.Duration) float64 {
	if len(values) == 0 {
		return 0
	}

	var sum float64
	for _, value := range values {
		sum += float64(value.Nanoseconds())
	}

	return sum / float64(len(values))
}
