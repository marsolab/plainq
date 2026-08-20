package agent

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marsolab/plainq/internal/shared/pqerr"
)

const (
	defaultPageSize = uint32(100)
	maxPageSize     = uint32(100)
)

var (
	resourceNamePattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	namePrefixPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

func validateAgentName(value string) (string, error) {
	if !resourceNamePattern.MatchString(value) {
		return "", fmt.Errorf("invalid agent name: %w", pqerr.ErrInvalidInput)
	}

	return value, nil
}

func validateCredentialName(value string) (string, error) {
	if !resourceNamePattern.MatchString(value) {
		return "", fmt.Errorf("invalid credential name: %w", pqerr.ErrInvalidInput)
	}

	return value, nil
}

func validateNamePrefix(value string) error {
	if value == "" {
		return nil
	}

	if !namePrefixPattern.MatchString(value) {
		return fmt.Errorf("invalid name prefix: %w", pqerr.ErrInvalidInput)
	}

	return nil
}

func validateULID(value, field string) error {
	parsed, err := ulid.ParseStrict(value)
	if err != nil || parsed.String() != value {
		return fmt.Errorf("invalid %s: %w", field, pqerr.ErrInvalidID)
	}

	return nil
}

func pageSize(value uint32) (uint32, error) {
	if value == 0 {
		return defaultPageSize, nil
	}

	if value > maxPageSize {
		return 0, fmt.Errorf("page limit exceeds %d: %w", maxPageSize, pqerr.ErrInvalidInput)
	}

	return value, nil
}

type agentCursor struct {
	name string
	id   string
}

func parseAgentCursor(value string) (agentCursor, error) {
	if value == "" {
		return agentCursor{}, nil
	}

	parts := strings.Split(value, "\x00")
	if len(parts) != 2 {
		return agentCursor{}, fmt.Errorf("invalid agent cursor: %w", pqerr.ErrInvalidInput)
	}

	if _, err := validateAgentName(parts[0]); err != nil {
		return agentCursor{}, fmt.Errorf("invalid agent cursor: %w", pqerr.ErrInvalidInput)
	}

	if err := validateULID(parts[1], "agent cursor ID"); err != nil {
		return agentCursor{}, fmt.Errorf("invalid agent cursor: %w", pqerr.ErrInvalidInput)
	}

	return agentCursor{name: parts[0], id: parts[1]}, nil
}

func validateCredentialCursor(value string) error {
	if value == "" {
		return nil
	}

	if err := validateULID(value, "credential cursor"); err != nil {
		return fmt.Errorf("invalid credential cursor: %w", pqerr.ErrInvalidInput)
	}

	return nil
}

func validateExpiry(
	value *timestamppb.Timestamp,
	now time.Time,
	maxTTL time.Duration,
) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}

	if err := value.CheckValid(); err != nil {
		return nil, fmt.Errorf("invalid credential expiry: %w", pqerr.ErrInvalidInput)
	}

	expiresAt := value.AsTime().UTC()
	if !expiresAt.After(now) {
		return nil, fmt.Errorf("credential expiry must be in the future: %w", pqerr.ErrInvalidInput)
	}

	if maxTTL <= 0 {
		return nil, errors.New("credential expiry policy is invalid")
	}

	if expiresAt.After(now.Add(maxTTL)) {
		return nil, fmt.Errorf("credential expiry exceeds policy: %w", pqerr.ErrInvalidInput)
	}

	return &expiresAt, nil
}
