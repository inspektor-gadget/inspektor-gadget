package main

import (
	"strings"

	wapc "github.com/wapc/wapc-guest-tinygo"
)

func main() {
	wapc.RegisterFunctions(wapc.Functions{
		"Init":        Init,
		"column_args": column_args,
	})
}

func Init(payload []byte) ([]byte, error) {
	return nil, nil
}

// columns_args returns the string representation of the args column.
// It's stored as a concatenation of strings separated by null.
func column_args(payload []byte) ([]byte, error) {
	buf := []byte{}
	args := []string{}

	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if c == 0 {
			args = append(args, string(buf))
			buf = []byte{}
		} else {
			buf = append(buf, c)
		}
	}

	return []byte(strings.Join(args, " ")), nil
}
