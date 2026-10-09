package runner

import (
	"strconv"
	"time"

	timeutil "github.com/projectdiscovery/utils/time"
)

const (
	// minTimeout is the smallest timeout used as-is. Anything below it is
	// treated as unset (e.g. a legacy SDK caller passing a millisecond count as
	// a time.Duration) and replaced with the scan type default.
	minTimeout = time.Millisecond
	// lowTimeout is the threshold below which a warning is shown, as such a
	// value is most likely a number of seconds written for releases that parsed
	// a bare -timeout as seconds.
	lowTimeout = 100 * time.Millisecond
)

// millisecondDuration is a flag.Value for -timeout. A bare number is read as
// milliseconds, as documented and as before the flag became a duration, while
// values with a unit (e.g. "500ms", "2s") are parsed as durations.
type millisecondDuration struct {
	value *time.Duration
}

func newMillisecondDuration(value *time.Duration, defaultValue time.Duration) *millisecondDuration {
	*value = defaultValue
	return &millisecondDuration{value: value}
}

func (m *millisecondDuration) Set(s string) error {
	// A bare number is milliseconds. Parsing it with the unit appended lets
	// the duration parser reject values that overflow time.Duration.
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		s += "ms"
	}
	d, err := timeutil.ParseDuration(s)
	if err != nil {
		return err
	}
	*m.value = d
	return nil
}

func (m *millisecondDuration) String() string {
	if m.value == nil {
		return ""
	}
	return m.value.String()
}
