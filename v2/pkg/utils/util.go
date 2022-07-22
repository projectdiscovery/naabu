package utils

func MapKeysToSliceInt(m map[int]struct{}) (s []int) {
	for k := range m {
		s = append(s, k)
	}
	return
}
