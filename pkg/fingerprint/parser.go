package fingerprint

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

// ServiceProbe represents a single Probe directive from the nmap-service-probes file.
type ServiceProbe struct {
	Protocol     string
	Name         string
	Data         []byte
	Ports        *PortSet
	SSLPorts     *PortSet
	TotalWaitMS  int
	TCPWrappedMS int
	Rarity       int
	Fallback     string
	Matches      []*Match
	SoftMatches  []*Match
}

// WaitDuration returns the TotalWaitMS as a time.Duration.
func (p *ServiceProbe) WaitDuration() time.Duration {
	if p.TotalWaitMS > 0 {
		return time.Duration(p.TotalWaitMS) * time.Millisecond
	}
	return 5 * time.Second
}

// Match represents a match or softmatch directive.
type Match struct {
	Service    string
	Pattern    *regexp2.Regexp
	PatternStr string
	Product    string
	Version    string
	Info       string
	Hostname   string
	OS         string
	DeviceType string
	CPEs       []string

	// Pre-computed fields for fast rejection (set during parsing).
	// literalPrefix is the longest literal byte sequence at the start of the
	// pattern (after ^), converted to Latin-1. Patterns whose prefix doesn't
	// appear in the response are skipped without running the regex engine.
	literalPrefix   string
	prefixAnchored  bool // true if pattern starts with ^
	prefixFoldCase  bool // true if pattern has 'i' flag
}

// prefixMatches checks whether the literal prefix extracted from the regex
// pattern appears in the response. Returns true if the prefix is empty
// (can't pre-filter), if it matches, or false for a definitive rejection.
func (m *Match) prefixMatches(latin1Response string) bool {
	if len(m.literalPrefix) == 0 {
		return true
	}
	if m.prefixAnchored {
		if m.prefixFoldCase {
			if len(latin1Response) < len(m.literalPrefix) {
				return false
			}
			return strings.EqualFold(latin1Response[:len(m.literalPrefix)], m.literalPrefix)
		}
		return strings.HasPrefix(latin1Response, m.literalPrefix)
	}
	if m.prefixFoldCase {
		return containsFold(latin1Response, m.literalPrefix)
	}
	return strings.Contains(latin1Response, m.literalPrefix)
}

func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if strings.EqualFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

// Apply substitutes regex capture group references ($1..$9) into the match templates.
func (m *Match) Apply(submatches []string) *MatchResult {
	return &MatchResult{
		Service:    m.Service,
		Product:    substituteGroups(m.Product, submatches),
		Version:    substituteGroups(m.Version, submatches),
		Info:       substituteGroups(m.Info, submatches),
		Hostname:   substituteGroups(m.Hostname, submatches),
		OS:         substituteGroups(m.OS, submatches),
		DeviceType: substituteGroups(m.DeviceType, submatches),
		CPEs:       substituteGroupsList(m.CPEs, submatches),
	}
}

// MatchResult is the result after applying capture groups to a Match.
type MatchResult struct {
	Service    string
	Product    string
	Version    string
	Info       string
	Hostname   string
	OS         string
	DeviceType string
	CPEs       []string
}

// PortSet holds a set of port numbers for fast lookup.
type PortSet struct {
	ports map[int]bool
}

func NewPortSet() *PortSet {
	return &PortSet{ports: make(map[int]bool)}
}

func (ps *PortSet) Add(port int) {
	ps.ports[port] = true
}

func (ps *PortSet) Contains(port int) bool {
	return ps.ports[port]
}

func (ps *PortSet) Len() int {
	return len(ps.ports)
}

// ProbeDB holds all parsed probes and the global exclude list.
type ProbeDB struct {
	Probes     []*ServiceProbe
	ExcludeTCP *PortSet
	ExcludeUDP *PortSet
}

// ParseProbeFile reads and parses an nmap-service-probes file.
func ParseProbeFile(path string) (*ProbeDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening probe file: %w", err)
	}
	defer f.Close()
	return ParseProbes(f)
}

// ParseProbes reads and parses nmap-service-probes content from a reader.
func ParseProbes(r io.Reader) (*ProbeDB, error) {
	db := &ProbeDB{
		ExcludeTCP: NewPortSet(),
		ExcludeUDP: NewPortSet(),
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	var current *ServiceProbe

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "Exclude ") {
			if err := parseExclude(line, db); err != nil {
				return nil, err
			}
			continue
		}

		if strings.HasPrefix(line, "Probe ") {
			probe, err := parseProbe(line)
			if err != nil {
				return nil, err
			}
			if current != nil {
				db.Probes = append(db.Probes, current)
			}
			current = probe
			continue
		}

		if current == nil {
			continue
		}

		switch {
		case strings.HasPrefix(line, "match "):
			m, err := parseMatch(line[6:])
			if err != nil {
				continue
			}
			current.Matches = append(current.Matches, m)

		case strings.HasPrefix(line, "softmatch "):
			m, err := parseMatch(line[10:])
			if err != nil {
				continue
			}
			current.SoftMatches = append(current.SoftMatches, m)

		case strings.HasPrefix(line, "ports "):
			current.Ports = parsePorts(line[6:])

		case strings.HasPrefix(line, "sslports "):
			current.SSLPorts = parsePorts(line[9:])

		case strings.HasPrefix(line, "totalwaitms "):
			current.TotalWaitMS, _ = strconv.Atoi(strings.TrimSpace(line[12:]))

		case strings.HasPrefix(line, "tcpwrappedms "):
			current.TCPWrappedMS, _ = strconv.Atoi(strings.TrimSpace(line[13:]))

		case strings.HasPrefix(line, "rarity "):
			current.Rarity, _ = strconv.Atoi(strings.TrimSpace(line[7:]))

		case strings.HasPrefix(line, "fallback "):
			current.Fallback = strings.TrimSpace(line[9:])
		}
	}

	if current != nil {
		db.Probes = append(db.Probes, current)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading probes: %w", err)
	}

	return db, nil
}

func parseProbe(line string) (*ServiceProbe, error) {
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		return nil, fmt.Errorf("malformed probe line: %s", line)
	}

	proto := parts[1]
	if proto != "TCP" && proto != "UDP" {
		return nil, fmt.Errorf("unknown protocol %q in probe line", proto)
	}

	name := parts[2]
	data, err := parseProbeData(parts[3])
	if err != nil {
		return nil, fmt.Errorf("parsing probe data for %s: %w", name, err)
	}

	return &ServiceProbe{
		Protocol:    proto,
		Name:        name,
		Data:        data,
		Ports:       NewPortSet(),
		SSLPorts:    NewPortSet(),
		Rarity:      5,
		TotalWaitMS: 5000,
	}, nil
}

func parseProbeData(s string) ([]byte, error) {
	if len(s) < 3 || s[0] != 'q' {
		return nil, fmt.Errorf("expected q-string, got %q", s)
	}
	delim := s[1]
	rest := s[2:]
	idx := strings.LastIndex(rest, string(delim))
	if idx < 0 {
		return nil, fmt.Errorf("unterminated q-string: %q", s)
	}
	return decodeNmapEscapes(rest[:idx]), nil
}

func decodeNmapEscapes(s string) []byte {
	var buf []byte
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'x':
				if i+3 < len(s) {
					val, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
					if err == nil {
						buf = append(buf, byte(val))
						i += 4
						continue
					}
				}
			case 'n':
				buf = append(buf, '\n')
				i += 2
				continue
			case 'r':
				buf = append(buf, '\r')
				i += 2
				continue
			case 't':
				buf = append(buf, '\t')
				i += 2
				continue
			case '0':
				buf = append(buf, 0)
				i += 2
				continue
			case 'a':
				buf = append(buf, '\a')
				i += 2
				continue
			case '\\':
				buf = append(buf, '\\')
				i += 2
				continue
			}
		}
		buf = append(buf, s[i])
		i++
	}
	return buf
}

// parseMatch parses a match/softmatch line after the directive keyword.
// Uses regexp2 (Perl-compatible regex) so all nmap patterns are supported.
func parseMatch(s string) (*Match, error) {
	spaceIdx := strings.IndexByte(s, ' ')
	if spaceIdx < 0 {
		return nil, fmt.Errorf("no service name in match")
	}
	service := s[:spaceIdx]
	rest := s[spaceIdx+1:]

	if len(rest) < 2 || rest[0] != 'm' {
		return nil, fmt.Errorf("expected m-string in match")
	}

	delim := rest[1]
	patternAndRest := rest[2:]

	patEnd := findMatchPatternEnd(patternAndRest, string(delim))
	if patEnd < 0 {
		return nil, fmt.Errorf("unterminated pattern in match")
	}

	patternStr := patternAndRest[:patEnd]
	flagsAndFields := patternAndRest[patEnd+1:]

	flags := ""
	fieldsPart := flagsAndFields
	if len(flagsAndFields) > 0 && flagsAndFields[0] != ' ' {
		flagEnd := strings.IndexByte(flagsAndFields, ' ')
		if flagEnd < 0 {
			flags = flagsAndFields
			fieldsPart = ""
		} else {
			flags = flagsAndFields[:flagEnd]
			fieldsPart = flagsAndFields[flagEnd+1:]
		}
	}

	var regexOpts regexp2.RegexOptions
	if strings.Contains(flags, "s") {
		regexOpts |= regexp2.Singleline
	}
	if strings.Contains(flags, "i") {
		regexOpts |= regexp2.IgnoreCase
	}

	compiled, err := regexp2.Compile(patternStr, regexOpts)
	if err != nil {
		return nil, fmt.Errorf("compiling regex %q: %w", patternStr, err)
	}
	compiled.MatchTimeout = 5 * time.Second

	prefixBytes, anchored := extractRegexLiteralPrefix(patternStr)
	m := &Match{
		Service:        service,
		Pattern:        compiled,
		PatternStr:     patternStr,
		literalPrefix:  bytesToLatin1(prefixBytes),
		prefixAnchored: anchored,
		prefixFoldCase: strings.Contains(flags, "i"),
	}

	parseMatchFields(fieldsPart, m)
	return m, nil
}

func findMatchPatternEnd(s, delim string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], delim) {
			return i
		}
	}
	return -1
}

func parseMatchFields(s string, m *Match) {
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		if len(s) == 0 {
			break
		}

		var key byte
		if len(s) >= 2 && s[1] == '/' {
			key = s[0]
			s = s[2:]
		} else if strings.HasPrefix(s, "cpe:") {
			cpe, rest := extractCPE(s)
			if cpe != "" {
				m.CPEs = append(m.CPEs, cpe)
			}
			s = rest
			continue
		} else {
			nextSpace := strings.IndexByte(s, ' ')
			if nextSpace < 0 {
				break
			}
			s = s[nextSpace+1:]
			continue
		}

		val, rest := extractDelimitedField(s, "/")
		s = rest

		switch key {
		case 'p':
			m.Product = val
		case 'v':
			m.Version = val
		case 'i':
			m.Info = val
		case 'h':
			m.Hostname = val
		case 'o':
			m.OS = val
		case 'd':
			m.DeviceType = val
		}
	}
}

func extractCPE(s string) (cpe, rest string) {
	i := 4
	for i < len(s) {
		if s[i] == ' ' {
			return s[:i], s[i+1:]
		}
		i++
	}
	return s, ""
}

func extractDelimitedField(s, delim string) (value, rest string) {
	var buf strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			buf.WriteByte(s[i+1])
			i += 2
			continue
		}
		if strings.HasPrefix(s[i:], delim) {
			return buf.String(), s[i+len(delim):]
		}
		buf.WriteByte(s[i])
		i++
	}
	return buf.String(), ""
}

func parsePorts(s string) *PortSet {
	ps := NewPortSet()
	s = strings.TrimSpace(s)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.IndexByte(part, '-'); idx > 0 {
			lo, err1 := strconv.Atoi(part[:idx])
			hi, err2 := strconv.Atoi(part[idx+1:])
			if err1 == nil && err2 == nil {
				for p := lo; p <= hi; p++ {
					ps.Add(p)
				}
			}
		} else {
			if p, err := strconv.Atoi(part); err == nil {
				ps.Add(p)
			}
		}
	}
	return ps
}

func parseExclude(line string, db *ProbeDB) error {
	rest := strings.TrimSpace(line[8:])
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "T:") {
			ports := parsePorts(part[2:])
			for p := range ports.ports {
				db.ExcludeTCP.Add(p)
			}
		} else if strings.HasPrefix(part, "U:") {
			ports := parsePorts(part[2:])
			for p := range ports.ports {
				db.ExcludeUDP.Add(p)
			}
		} else {
			ports := parsePorts(part)
			for p := range ports.ports {
				db.ExcludeTCP.Add(p)
				db.ExcludeUDP.Add(p)
			}
		}
	}
	return nil
}

func substituteGroups(template string, submatches []string) string {
	if template == "" || len(submatches) == 0 {
		return template
	}
	result := template
	upper := len(submatches) - 1
	if upper > 9 {
		upper = 9
	}
	for i := upper; i >= 1; i-- {
		result = strings.ReplaceAll(result, "$"+strconv.Itoa(i), submatches[i])
	}
	return result
}

func substituteGroupsList(templates []string, submatches []string) []string {
	if len(templates) == 0 {
		return nil
	}
	out := make([]string, len(templates))
	for i, t := range templates {
		out[i] = substituteGroups(t, submatches)
	}
	return out
}

// extractRegexLiteralPrefix extracts the longest literal byte prefix from a
// regex pattern. This is used for fast rejection: if the prefix doesn't appear
// in the response, the full regex match is skipped.
func extractRegexLiteralPrefix(pattern string) (prefix []byte, anchored bool) {
	if len(pattern) == 0 {
		return nil, false
	}

	i := 0
	if pattern[0] == '^' {
		anchored = true
		i = 1
	}

	var buf []byte
	for i < len(pattern) {
		c := pattern[i]
		switch c {
		case '.', '*', '+', '?', '[', '(', '{', '|', '$', ')':
			return buf, anchored
		case '\\':
			if i+1 >= len(pattern) {
				return buf, anchored
			}
			next := pattern[i+1]
			switch next {
			case 'd', 'D', 'w', 'W', 's', 'S', 'b', 'B', 'A', 'Z', 'z', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				return buf, anchored
			case 'x':
				if i+3 < len(pattern) {
					hi := unhex(pattern[i+2])
					lo := unhex(pattern[i+3])
					if hi >= 0 && lo >= 0 {
						buf = append(buf, byte(hi<<4|lo))
						i += 4
						continue
					}
				}
				return buf, anchored
			case 'n':
				buf = append(buf, '\n')
				i += 2
			case 'r':
				buf = append(buf, '\r')
				i += 2
			case 't':
				buf = append(buf, '\t')
				i += 2
			case '0':
				buf = append(buf, 0)
				i += 2
			default:
				buf = append(buf, next)
				i += 2
			}
		default:
			buf = append(buf, c)
			i++
		}
	}
	return buf, anchored
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// FindSubmatch is a helper that bridges regexp2.Regexp to return submatches
// as a string slice (similar to Go's regexp.FindSubmatch).
// Input is converted to Latin-1 encoding so that each byte maps directly to
// a Unicode code point, ensuring binary patterns like \xff work correctly.
func FindSubmatch(re *regexp2.Regexp, input []byte) []string {
	latin1 := bytesToLatin1(input)
	m, err := re.FindStringMatch(latin1)
	if err != nil || m == nil {
		return nil
	}
	groups := m.Groups()
	result := make([]string, len(groups))
	for i, g := range groups {
		result[i] = g.String()
	}
	return result
}

// bytesToLatin1 converts raw bytes to a string where each byte maps directly
// to its Unicode code point (ISO 8859-1 / Latin-1). This is essential for
// binary protocol matching because nmap's \xHH regex escapes refer to byte
// values, not UTF-8 sequences.
func bytesToLatin1(b []byte) string {
	runes := make([]rune, len(b))
	for i, v := range b {
		runes[i] = rune(v)
	}
	return string(runes)
}
