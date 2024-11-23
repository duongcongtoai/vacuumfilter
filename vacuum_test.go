package cuckoo

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func newStrings(num int) []string {
	strs := make([]string, num)
	for i := range strs {
		strs[i] = uuid.NewString()
	}
	return strs
}

func Test_Vacuum(t *testing.T) {
	f := VacuumFilter{}
	// n := 1 << 20
	n := 100000
	f.Init(n*2, 4, 400)

	alienKeys := newStrings(n)
	exist := newStrings(n)
	for i := 0; i < n; i++ {
		inserted := f.Insert([]byte(exist[i]))
		assert.True(t, inserted)
	}
	falsePositive := 0
	for i := 0; i < len(alienKeys); i++ {
		exist := f.Lookup([]byte(alienKeys[i]))
		if exist {
			falsePositive++
		}
	}
	assert.Less(t, float64(falsePositive)/float64(len(alienKeys)), 0.001)

	falseNegatives := []int{}
	for i := 0; i < len(exist); i++ {
		exist := f.Lookup([]byte(exist[i]))
		if !exist {
			falseNegatives = append(falseNegatives, i)
		}
	}
	assert.Equal(t, 0, len(falseNegatives))

	for i := 0; i < len(exist); i++ {
		deleted := f.Delete([]byte(exist[i]))
		assert.True(t, deleted)
	}
	falsePositive = 0
	for i := 0; i < len(exist); i++ {
		exist := f.Lookup([]byte(exist[i]))
		if exist {
			falsePositive++
		}
	}
	assert.Less(t, float64(falsePositive)/float64(len(exist)), 0.001)

	// the filter is empty now
	// insert new element and check
	exist2 := newStrings(n)
	for i := 0; i < n; i++ {
		inserted := f.Insert([]byte(exist2[i]))
		assert.True(t, inserted)
	}
	falsePositive = 0
	for i := 0; i < len(exist); i++ {
		exist := f.Lookup([]byte(exist[i]))
		if exist {
			falsePositive++
		}
	}
	for i := 0; i < len(alienKeys); i++ {
		exist := f.Lookup([]byte(alienKeys[i]))
		if exist {
			falsePositive++
		}
	}
	for i := 0; i < len(exist2); i++ {
		exist := f.Lookup([]byte(exist2[i]))
		if !exist {
			falseNegatives = append(falseNegatives, i)
		}
	}
	assert.Empty(t, falseNegatives)
	assert.Less(t, float64(falsePositive)/float64(len(exist)+len(alienKeys)), 0.001)
}
