package utils

import "strconv"

func ParseInt(s string) (int, error) {
	return strconv.Atoi(s)
}
