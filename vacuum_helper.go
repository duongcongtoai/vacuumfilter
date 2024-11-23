package cuckoo

func roundDown(a, b uint64) uint64 {
	return a - (a % b)
}

// Helper function to sort two values in descending order
func (f *SemiSortCuckooFilter) SortPair(a, b *int64) {
	if *a < *b {
		*a, *b = *b, *a
	}
}
