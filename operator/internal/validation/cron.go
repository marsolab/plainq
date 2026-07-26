package validation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// cronField describes the permitted range of one field.
type cronField struct {
	name string
	min  int
	max  int
	// names are the symbolic values accepted in addition to numbers.
	names map[string]int
}

var cronFields = []cronField{
	{name: "minute", min: 0, max: 59},
	{name: "hour", min: 0, max: 23},
	{name: "day of month", min: 1, max: 31},
	{name: "month", min: 1, max: 12, names: map[string]int{
		"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
		"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	}},
	{name: "day of week", min: 0, max: 7, names: map[string]int{
		"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
	}},
}

// ValidateCron checks a standard five-field cron expression.
//
// A schedule that does not parse fails silently at 3am, when nobody is
// watching and the backup everyone assumes exists never ran. Rejecting it at
// admission is the only moment anyone is looking.
func ValidateCron(expr string) error {
	expr = strings.TrimSpace(expr)

	if descriptor, ok := strings.CutPrefix(expr, "@"); ok {
		switch strings.ToLower(descriptor) {
		case "yearly", "annually", "monthly", "weekly", "daily", "midnight", "hourly":
			return nil
		}

		return fmt.Errorf("unknown descriptor %q", expr)
	}

	parts := strings.Fields(expr)
	if len(parts) != len(cronFields) {
		return fmt.Errorf("expected %d fields, got %d", len(cronFields), len(parts))
	}

	for i, part := range parts {
		if err := validateCronField(part, cronFields[i]); err != nil {
			return fmt.Errorf("%s: %w", cronFields[i].name, err)
		}
	}

	return nil
}

func validateCronField(expr string, f cronField) error {
	for _, item := range strings.Split(expr, ",") {
		if err := validateCronItem(item, f); err != nil {
			return err
		}
	}

	return nil
}

func validateCronItem(item string, f cronField) error {
	if item == "" {
		return errors.New("empty value")
	}

	// Step: <range>/<n>.
	rangePart := item

	if base, step, ok := strings.Cut(item, "/"); ok {
		rangePart = base

		n, err := strconv.Atoi(step)
		if err != nil || n < 1 {
			return fmt.Errorf("invalid step %q", step)
		}
	}

	if rangePart == "*" {
		return nil
	}

	if lo, hi, ok := strings.Cut(rangePart, "-"); ok {
		low, err := cronValue(lo, f)
		if err != nil {
			return err
		}

		high, err := cronValue(hi, f)
		if err != nil {
			return err
		}

		if low > high {
			return fmt.Errorf("range %q is inverted", rangePart)
		}

		return nil
	}

	_, err := cronValue(rangePart, f)

	return err
}

func cronValue(token string, f cronField) (int, error) {
	if f.names != nil {
		if v, ok := f.names[strings.ToLower(token)]; ok {
			return v, nil
		}
	}

	v, err := strconv.Atoi(token)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q", token)
	}

	if v < f.min || v > f.max {
		return 0, fmt.Errorf("value %d out of range %d-%d", v, f.min, f.max)
	}

	return v, nil
}
