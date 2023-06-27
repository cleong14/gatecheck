package filter

type Predicate[T any] func(T) bool

func Filter[T any](input []T, keep Predicate[T]) []T {
	n := 0
	output := make([]T, 0, len(input))
	for i := range input {
		if keep(input[i]) {
			output = append(output, input[i])
			n++
		}
	}
	return output[:n]
}
