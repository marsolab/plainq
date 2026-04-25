package litestore

import (
	"strings"
	"testing"

	"github.com/maxatome/go-testdeep/td"
)

func Test_queryCreateQueueTable(t *testing.T) {
	var tests = map[string]struct {
		input    string
		expected string
	}{
		"empty string as input":       {input: "", expected: "create table (\n"},
		"special characters as input": {input: "@!#$%^?", expected: "create table @!#$%^?"},
		"long input string":           {input: strings.Repeat("a", 100000), expected: "create table " + strings.Repeat("a", 100000)},
		"numeric input":               {input: "123456789", expected: "create table 123456789"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			createdQuery := queryCreateQueueTable(tt.input)
			// the sql query is expected to start with `create table` and the passed input
			td.Cmp(t, createdQuery[:len(tt.expected)], tt.expected)
		})
	}
}
