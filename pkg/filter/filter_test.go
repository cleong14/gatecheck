package filter

import (
	"testing"
)

func TestFilterInPlace(t *testing.T) {
	items := 1_000_000
	input := make([]int, items, items)

	for i := 0; i < items; i++ {
		input[i] = i
	}

	input = Filter[int](input, func(a int) bool { return a%2 == 0 })

	for i := 0; i < len(input); i++ {
		if input[i]%2 != 0 {
			t.Fatalf("want: value %% 2 == 0, got: %d", input[i])
		}
	}
}
