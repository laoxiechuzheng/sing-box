package tls

import (
	"net/netip"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// serverNameAllowlist restricts which SNI values a server accepts. Names match
// case-insensitively; "*.example.com" matches any subdomain of example.com but
// not example.com itself. A ClientHello without SNI never matches.
type serverNameAllowlist struct {
	exact    map[string]struct{}
	suffixes []string
}

func newServerNameAllowlist(names []string) (*serverNameAllowlist, error) {
	if len(names) == 0 {
		return nil, nil
	}
	allowlist := &serverNameAllowlist{exact: make(map[string]struct{}, len(names))}
	for _, name := range names {
		normalized := normalizeServerName(name)
		host, wildcard := strings.CutPrefix(normalized, "*.")
		if !isServerNameHost(host) {
			return nil, E.New("invalid server_name_allowlist entry: ", strconv.Quote(name))
		}
		if wildcard {
			allowlist.suffixes = append(allowlist.suffixes, "."+host)
		} else {
			allowlist.exact[host] = struct{}{}
		}
	}
	return allowlist, nil
}

func (l *serverNameAllowlist) allows(serverName string) bool {
	serverName = normalizeServerName(serverName)
	if serverName == "" {
		return false
	}
	if _, loaded := l.exact[serverName]; loaded {
		return true
	}
	for _, suffix := range l.suffixes {
		if strings.HasSuffix(serverName, suffix) {
			return true
		}
	}
	return false
}

func normalizeServerName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// isServerNameHost reports whether name is a DNS host name that can appear in
// SNI. IP literals are rejected because RFC 6066 forbids them in SNI.
func isServerNameHost(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}
