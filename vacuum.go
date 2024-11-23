package cuckoo

import (
	"encoding/binary"
	"math"
	"math/rand"
	"sync"
	"unsafe"

	"github.com/twmb/murmur3"
)

var (
	fpLen uint64 = 16
)

type SemiSortCuckooFilter struct {
	n                 int
	m                 int
	memoryConsumption uint64
	max2Power         int
	bigSeg            int
	len               [4]int
	filledCell        int
	fullBucket        int
	maxKickSteps      int
	table             []uint32
	encodeTable       [1 << 16]uint32
	decodeTable       [1 << 16]uint32
	debugFlag         bool
	balance           bool
	lock              sync.RWMutex
}

// PositionHash maps an element to a position in the filter
func (f *SemiSortCuckooFilter) PositionHash(ele int64) int64 {
	return (ele%int64(f.n) + int64(f.n)) % int64(f.n)
}

func UpperPower2(x int) int {
	ret := 1
	for ret < x {
		ret <<= 1
	}
	return ret
}

// Init initializes the SemiSortCuckooFilter
func (f *SemiSortCuckooFilter) Init(maxItem, m, step int) {
	// Calculate the number of buckets (_n)
	n := int(float64(maxItem) / 0.96 / 4)

	if n < 10000 {
		if n < 256 {
			f.bigSeg = UpperPower2(n)
		} else {
			f.bigSeg = UpperPower2(n / 4)
		}
		n = RoundUp(n, f.bigSeg)
		f.len[0] = f.bigSeg - 1
		f.len[1] = f.bigSeg - 1
		f.len[2] = f.bigSeg - 1
		f.len[3] = f.bigSeg - 1
	} else {
		f.bigSeg = 0
		f.bigSeg = max(f.bigSeg, ProperAltRange(n, 0, f.len[:]))
		newN := RoundUp(n, f.bigSeg)
		n = newN

		f.bigSeg--
		f.len[0] = f.bigSeg
		for i := 1; i < 4; i++ {
			f.len[i] = ProperAltRange(n, i, f.len[:]) - 1
		}
		f.len[0] = max(f.len[0], 1024)
		f.len[3] = (f.len[3]+1)*2 - 1
	}

	// Initialize the SemiSortCuckooFilter properties
	f.n = n
	f.m = m
	f.maxKickSteps = step
	f.filledCell = 0
	f.fullBucket = 0

	// Calculate memory consumption
	howManyBits := uint64(f.n) * uint64(f.m) * uint64(fpLen-1)
	f.memoryConsumption = uint64(RoundUp(int(howManyBits+64), 8))/8 + 8

	// Determine the maximum power of 2 less than or equal to _n
	f.max2Power = 1
	for f.max2Power*2 < n {
		f.max2Power <<= 1
	}

	var toCast = make([]byte, f.memoryConsumption)
	casted := *(*[]uint32)(unsafe.Pointer(&toCast))
	// Allocate memory for the filter table
	f.table = casted[:len(toCast)/4]

	temp := func(i int) int {
		if i == 0 {
			return 1
		}
		return i + 1
	}

	// Initialize the encode and decode tables
	index := 0
	for i := 0; i < 16; i++ {
		for j := 0; j < temp(i); j++ {
			for k := 0; k < temp(j); k++ {
				for l := 0; l < temp(k); l++ {
					plainBit := (i << 12) + (j << 8) + (k << 4) + l
					f.encodeTable[plainBit] = uint32(index)
					f.decodeTable[index] = uint32(plainBit)
					index++
				}
			}
		}
	}
}

// Clear resets the filter
func (f *SemiSortCuckooFilter) Clear() {
	f.filledCell = 0
	for i := range f.table {
		f.table[i] = 0
	}
}

// RoundUp rounds up to the nearest multiple of b
func RoundUp(a, b int) int {
	return ((a + b - 1) / b) * b
}

// HashUtilMurmurHash64 is a placeholder for the MurmurHash function
func HashUtilMurmurHash64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return uint64(h)
}
func HashUtilMurmurHash64Raw(data []byte) uint64 {
	return murmur3.Sum64(data)
}

// Fingerprint generates a fingerprint for an element
func (f *SemiSortCuckooFilter) Fingerprint(ele uint64) uint64 {
	return HashUtilMurmurHash64(ele^0x192837319273)%((1<<fpLen)-1) + 1
}

// GetLoadFactor computes the load factor
func (f *SemiSortCuckooFilter) GetLoadFactor() float64 {
	return float64(f.filledCell) / float64(f.n) / float64(f.m)
}

// VacuumFilter is a type of SemiSortCuckooFilter
type VacuumFilter struct {
	SemiSortCuckooFilter
}

func (v *SemiSortCuckooFilter) Alternate(pos int64, fp int64) int64 {
	fpHash := fp * 0x5bd1e995
	seg := v.len[fp&3]
	return pos ^ int64(fpHash&int64(seg))
}

// Insert overrides Insert for VacuumFilter
func (v *SemiSortCuckooFilter) Insert(data []byte) bool {
	// Apply hash transformation
	ele := HashUtilMurmurHash64Raw(data)

	// Generate fingerprint and calculate primary and alternate positions
	fp := int64(v.Fingerprint(ele))
	cur1 := v.PositionHash(int64(ele))
	cur2 := v.Alternate(int64(cur1), fp)

	// Create storage for buckets
	store1 := make([]int64, 8)
	store2 := make([]int64, 8)

	// Get buckets at primary and alternate positions
	v.GetBucket((cur1), store1)
	v.GetBucket((cur2), store2)

	// Insert into the bucket with fewer elements
	if store1[v.m] <= store2[v.m] {
		if v.InsertToBucket(store1, fp) == 0 {
			v.filledCell++
			v.SetBucket((cur1), store1)
			return true
		}
	} else {
		if v.InsertToBucket(store2, fp) == 0 {
			v.filledCell++
			v.SetBucket((cur2), store2)
			return true
		}
	}

	// Randomly choose a bucket to kick an element
	rk := rand.Intn(v.m)
	var cur int64
	var curStore []int64
	if rand.Intn(2) == 0 {
		cur = (cur1)
		curStore = store1
	} else {
		cur = (cur2)
		curStore = store2
	}

	// Kick out a random element and insert the new one
	tmpFP := curStore[rk]
	curStore[rk] = fp
	v.SetBucket(cur, curStore)

	alt := v.Alternate(cur, tmpFP)

	for i := 0; i < v.maxKickSteps; i++ {
		// Fetch the bucket at the alternate position
		store1 = make([]int64, len(store1))
		v.GetBucket(alt, store1)

		if store1[v.m] == int64(v.m) { // If bucket is full
			for j := 0; j < v.m; j++ {
				nex := v.Alternate(alt, store1[j])
				v.GetBucket(nex, store2)

				if store2[v.m] < int64(v.m) {
					store2[v.m-1] = store1[j]
					store1[j] = tmpFP
					v.filledCell++
					v.SetBucket(nex, store2)
					v.SetBucket(alt, store1)
					return true
				}
			}

			rk = rand.Intn(v.m)
			fp = store1[rk]
			store1[rk] = tmpFP
			v.SetBucket(alt, store1)

			tmpFP = fp
			alt = v.Alternate(alt, tmpFP)
		} else { // If bucket is not full
			store1[v.m-1] = tmpFP
			v.filledCell++
			v.SetBucket(alt, store1)
			return true
		}
	}
	return false // Insertion failed after max kick steps
}

func (f *SemiSortCuckooFilter) SetBucket(pos int64, store []int64) {
	// 0. Sort the bucket in descending order
	f.SortPair(&store[0], &store[2])
	f.SortPair(&store[1], &store[3])
	f.SortPair(&store[0], &store[1])
	f.SortPair(&store[2], &store[3])
	f.SortPair(&store[1], &store[2])

	// 1. Compute the encoding
	var highBit uint64 = 0
	var lowBit uint64 = 0

	lowBit = (uint64(store[3]) & ((1 << (fpLen - 4)) - 1)) +
		((uint64(store[2]) & ((1 << (fpLen - 4)) - 1)) << (1 * (fpLen - 4))) +
		((uint64(store[1]) & ((1 << (fpLen - 4)) - 1)) << (2 * (fpLen - 4))) +
		((uint64(store[0]) & ((1 << (fpLen - 4)) - 1)) << (3 * (fpLen - 4)))

	highBit = ((uint64(store[3]) >> (fpLen - 4)) & ((1 << 4) - 1)) +
		(((uint64(store[2]) >> (fpLen - 4)) & ((1 << 4) - 1)) << 4) +
		(((uint64(store[1]) >> (fpLen - 4)) & ((1 << 4) - 1)) << 8) +
		(((uint64(store[0]) >> (fpLen - 4)) & ((1 << 4) - 1)) << 12)

	highEncode := uint64(f.encodeTable[highBit])
	allEncode := (highEncode << (4 * (fpLen - 4))) + lowBit

	bucketLength := (fpLen - 1) * 4
	startBitPos := uint64(pos) * uint64(bucketLength)
	endBitPos := startBitPos + uint64(bucketLength) - 1

	uint64Slice := *(*[]uint64)(unsafe.Pointer(&f.table))
	uint64Slice = uint64Slice[:len(uint64Slice)/2]
	// 2. Store into memory
	if roundDown(startBitPos, 64) == roundDown(endBitPos, 64) {

		unit := uint64Slice[roundDown(startBitPos, 64)/64]
		writingLowerBound := startBitPos & 63
		writingUpperBound := endBitPos & 63

		uint64Slice[roundDown(startBitPos, 64)/64] =
			(unit & (((1 << writingLowerBound) - 1) +
				(^(uint64(0)) - (^(uint64(0)) >> (63 - writingUpperBound))))) +
				((allEncode & ((1 << (writingUpperBound - writingLowerBound + 1)) - 1)) << writingLowerBound)
	} else {
		unit1 := uint64Slice[roundDown(startBitPos, 64)/64]
		unit2 := uint64Slice[roundDown(startBitPos, 64)/64+1]
		writingLowerBound := startBitPos & 63
		writingUpperBound := endBitPos & 63

		lowerPart := allEncode & ((1 << (64 - writingLowerBound)) - 1)
		higherPart := allEncode >> (64 - writingLowerBound)

		start_val :=
			(unit1 & ((1 << writingLowerBound) - 1)) +
				(lowerPart << writingLowerBound)
		start_val_2 := ((unit2 >> (writingUpperBound + 1)) << (writingUpperBound + 1)) + higherPart
		uint64Slice[roundDown(startBitPos, 64)/64] = start_val
		uint64Slice[roundDown(startBitPos, 64)/64+1] = start_val_2

	}
}

func (f *SemiSortCuckooFilter) GetBucket(pos int64, store []int64) {
	// Default:
	// Little Endian Store
	// Store by uint64
	// store[f.m] = bucket number

	// 1. Read the encoded bits from memory
	bucketLength := (fpLen - 1) * 4
	startBitPos := uint64(pos) * uint64(bucketLength)
	endBitPos := startBitPos + uint64(bucketLength) - 1
	var result uint64

	uint64Slice := *(*[]uint64)(unsafe.Pointer(&f.table))
	uint64Slice = uint64Slice[:len(uint64Slice)/2]

	if RoundDown(startBitPos, 64) == RoundDown(endBitPos, 64) {
		unit := uint64Slice[RoundDown(startBitPos, 64)/64]
		readingLowerBound := (startBitPos & 63)
		readingUpperBound := (endBitPos & 63)

		result = (unit & (math.MaxUint64 >> (63 - readingUpperBound))) >> readingLowerBound
	} else {
		unit1 := uint64Slice[RoundDown(startBitPos, 64)/64]
		unit2 := uint64Slice[RoundDown(startBitPos, 64)/64+1]

		readingLowerBound := startBitPos & 63
		readingUpperBound := endBitPos & 63

		t1 := unit1 >> readingLowerBound
		t2 := (unit2 & ((1 << (readingUpperBound + 1)) - 1)) << (64 - readingLowerBound)
		result = t1 + t2
	}

	// 2. Decode the 4 elements from the encoded bits
	decodeResult := int64(f.decodeTable[result>>(4*(fpLen-4))])

	store[3] = ((int64(result) & ((1 << (fpLen - 4)) - 1)) +
		((decodeResult & ((1 << 4) - 1)) << (fpLen - 4)))
	store[2] = (((int64(result) >> (1 * (fpLen - 4))) & ((1 << (fpLen - 4)) - 1)) +
		(((decodeResult >> 4) & ((1 << 4) - 1)) << (fpLen - 4)))
	store[1] = (((int64(result) >> (2 * (fpLen - 4))) & ((1 << (fpLen - 4)) - 1)) +
		(((decodeResult >> 8) & ((1 << 4) - 1)) << (fpLen - 4)))
	store[0] = (((int64(result) >> (3 * (fpLen - 4))) & ((1 << (fpLen - 4)) - 1)) +
		(((decodeResult >> 12) & ((1 << 4) - 1)) << (fpLen - 4)))

	// Count the number of non-zero elements in the bucket
	store[4] = 0
	if store[0] != 0 {
		store[4]++
	}
	if store[1] != 0 {
		store[4]++
	}
	if store[2] != 0 {
		store[4]++
	}
	if store[3] != 0 {
		store[4]++
	}
}

// Helper function to round down a number to the nearest multiple of b
func RoundDown(a, b uint64) uint64 {
	return a - (a % b)
}

func (f *SemiSortCuckooFilter) InsertToBucket(store []int64, fp int64) int {
	if store[f.m] == int64(f.m) {
		return 1 + 4
	} else {
		store[3] = fp
		return 0
	}
}

func (f *SemiSortCuckooFilter) Delete(data []byte) bool {
	// Hash the element
	ele := HashUtilMurmurHash64Raw(data)

	// Compute the fingerprint and primary position
	fp := int64(f.Fingerprint(ele))
	pos1 := f.PositionHash(int64(ele))

	// Attempt to delete from the primary bucket
	ok1 := f.DeleteInBucket(pos1, fp)
	if ok1 == 1 {
		return true
	}

	// Compute the alternate position
	pos2 := f.Alternate(pos1, fp)

	// Attempt to delete from the alternate bucket
	ok2 := f.DeleteInBucket(pos2, fp)
	return ok2 == 1
}

func (f *SemiSortCuckooFilter) DeleteInBucket(pos int64, fp int64) int {
	// Create a temporary storage for the bucket
	store := make([]int64, 8) // f.m is the number of slots per bucket

	// Retrieve the bucket contents from the filter
	f.GetBucket(pos, store)

	// Iterate through the bucket to find the fingerprint
	for i := 0; i < f.m; i++ {
		if store[i] == fp { // Match found
			store[i] = 0            // Remove the fingerprint by setting it to 0
			f.filledCell--          // Decrement the filled cell count
			f.SetBucket(pos, store) // Write the updated bucket back to the filter
			return 1                // Return success
		}
	}

	return 0 // Fingerprint not found
}

func (f *SemiSortCuckooFilter) Lookup(raw []byte) bool {
	// Hash the element
	ele := HashUtilMurmurHash64Raw(raw)

	// Generate the fingerprint and calculate the primary position
	fp := int64(f.Fingerprint(ele))
	pos1 := f.PositionHash(int64(ele))

	// Check the primary bucket
	ok1 := f.LookupInBucket(pos1, fp)
	if ok1 == 1 {
		return true
	}

	// Calculate the alternate position
	pos2 := f.Alternate(pos1, fp)

	// Assert the alternate position is consistent
	if pos1 != f.Alternate(pos2, fp) {
		panic("Inconsistent alternate position")
	}

	// Check the alternate bucket
	ok2 := f.LookupInBucket(pos2, fp)
	return ok2 == 1
}

func (f *SemiSortCuckooFilter) LookupInBucket(pos int64, fp int64) int {
	// Temporary storage for the bucket
	store := make([]int64, 8) // f.m is the number of slots per bucket

	// Retrieve the contents of the bucket at position `pos`
	f.GetBucket(pos, store)

	isFull := true // Assume the bucket is full initially

	// Iterate through the bucket
	for i := 0; i < f.m; i++ {
		if store[i] == fp { // If fingerprint is found, return success
			return 1
		}
		isFull = isFull && (store[i] != 0) // Update `isFull` based on empty slots
	}

	// If the bucket is full but the fingerprint is not found, return 2
	// Otherwise, return 3 indicating the bucket is not full
	if isFull {
		return 2
	}
	return 3
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ProperAltRange(M, i int, len []int) int {
	b := 4.0      // Slots per bucket
	lf := 0.95    // Target load factor
	altRange := 8 // Initial alternate range

	for altRange < M {
		f := (4.0 - float64(i)) * 0.25
		if BallsInBinsMaxLoad(f*b*lf*float64(M), float64(M)/float64(altRange)) < 0.97*b*float64(altRange) {
			return altRange
		}
		altRange <<= 1
	}
	return altRange
}

// SolveEquation solves the given equation using Newton's method.
func SolveEquation(c float64) float64 {
	x := c + 0.1
	for math.Abs(F(x, c)) > 0.001 {
		x -= F(x, c) / FDerivative(x, c)
	}
	return x
}

// F is the main function used in Newton's method.
func F(x, c float64) float64 {
	return 1 + x*(math.Log(c)-math.Log(x)+1) - c
}

// FDerivative is the derivative of F with respect to x.
func FDerivative(x, c float64) float64 {
	return math.Log(c) - math.Log(x)
}

// BallsInBinsMaxLoad calculates the maximum load based on the balls-in-bins model.
func BallsInBinsMaxLoad(balls, bins float64) float64 {
	if bins == 1 {
		return balls
	}

	c := balls / (bins * math.Log(bins))

	// If c is small, solve for a more accurate bound
	if c < 5 {
		dc := SolveEquation(c)
		return (dc - 1 + 2) * math.Log(bins)
	}

	// Use the asymptotic approximation for larger c
	return (balls / bins) + 1.5*math.Sqrt(2*balls/bins*math.Log(bins))
}

func uint32ToBytes(data []uint32) []byte {
	byteData := make([]byte, len(data)*4)
	for i, val := range data {
		binary.LittleEndian.PutUint32(byteData[i*4+0:i*4+4], val)
	}
	return byteData
}
