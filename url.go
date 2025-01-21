package url

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrEmptyURL   = errors.New("empty URL")
	ErrInvalidURL = errors.New("invalid URL format")
)

type RawURL struct {
	Original      string
	Scheme        string
	Opaque        string
	User          *Userinfo
	Host          string
	Path          string
	Query         string
	Fragment      string
	RawRequestURI string
}

type Userinfo struct {
	username    string
	password    string
	passwordSet bool
}

type ParseOptions struct {
	FallbackScheme     string
	AllowMissingScheme bool
}

func DefaultOptions() *ParseOptions {
	return &ParseOptions{
		FallbackScheme:     "https",
		AllowMissingScheme: true,
	}
}

func RawURLParseWithOptions(rawURL string, opts *ParseOptions) (*RawURL, error) {
	if len(rawURL) == 0 {
		return nil, ErrEmptyURL
	}

	result := &RawURL{
		Original: rawURL,
	}

	schemeEnd := strings.Index(rawURL, "://")
	remaining := rawURL

	if schemeEnd != -1 {
		result.Scheme = rawURL[:schemeEnd]
		remaining = rawURL[schemeEnd+3:]
	} else {

		if colonIndex := strings.Index(rawURL, ":"); colonIndex != -1 {
			beforeColon := rawURL[:colonIndex]
			if !strings.Contains(beforeColon, "/") && !strings.Contains(beforeColon, ".") {
				result.Scheme = beforeColon
				result.Opaque = rawURL[colonIndex+1:]
				return result, nil
			}
		}

		if opts != nil && opts.AllowMissingScheme {
			result.Scheme = opts.FallbackScheme
		}
	}

	pathStart := strings.Index(remaining, "/")
	authority := remaining
	if pathStart != -1 {
		authority = remaining[:pathStart]
		remaining = remaining[pathStart:]
	} else {
		remaining = "/"
	}

	if atIndex := strings.Index(authority, "@"); atIndex != -1 {
		userinfo := authority[:atIndex]
		authority = authority[atIndex+1:]

		result.User = &Userinfo{}
		if colonIndex := strings.Index(userinfo, ":"); colonIndex != -1 {
			result.User.username = userinfo[:colonIndex]
			result.User.password = userinfo[colonIndex+1:]
			result.User.passwordSet = true
		} else {
			result.User.username = userinfo
		}
	}

	if strings.HasPrefix(authority, "[") {
		closeBracket := strings.LastIndex(authority, "]")
		if closeBracket == -1 {
			return nil, ErrInvalidURL
		}

		result.Host = authority[:closeBracket+1]

		if len(authority) > closeBracket+1 {
			if authority[closeBracket+1] == ':' {
				result.Host = authority
			}
		}
	} else {

		result.Host = authority
	}

	if len(remaining) > 0 {

		if hashIndex := strings.Index(remaining, "#"); hashIndex != -1 {
			result.Fragment = remaining[hashIndex+1:]
			remaining = remaining[:hashIndex]
		}

		if queryIndex := strings.Index(remaining, "?"); queryIndex != -1 {
			result.Query = remaining[queryIndex+1:]
			remaining = remaining[:queryIndex]
		}

		result.Path = remaining
	}

	result.RawRequestURI = result.Path
	if result.Query != "" {
		result.RawRequestURI += "?" + result.Query
	}
	if result.Fragment != "" {
		result.RawRequestURI += "#" + result.Fragment
	}

	return result, nil
}

func Parse(rawURL string) (*RawURL, error) {
	return RawURLParseWithOptions(rawURL, DefaultOptions())
}

func RawURLParseStrict(rawURL string) (*RawURL, error) {
	return RawURLParseWithOptions(rawURL, nil)
}

func (u *RawURL) Hostname() string {

	return u.GetHostname()
}

func (u *RawURL) Port() string {
	return u.GetPort()
}

func (u *RawURL) BaseURL() string {
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}

type URLComponent int

const (
	Scheme URLComponent = iota
	Username
	Password
	Host
	Port
	Path
	Query
	Fragment
	RawURI
)

type RawURLBuilder struct {
	*RawURL
	workingURI string
}

func NewRawURLBuilder(u *RawURL) *RawURLBuilder {
	return &RawURLBuilder{
		RawURL:     u,
		workingURI: u.RawRequestURI,
	}
}

func (u *RawURL) FullString() string {
	var buf strings.Builder

	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteString("://")
	}

	if u.User != nil {
		buf.WriteString(u.User.username)
		if u.User.passwordSet {
			buf.WriteRune(':')
			buf.WriteString(u.User.password)
		}
		buf.WriteRune('@')
	}

	buf.WriteString(u.Host)
	buf.WriteString(u.Path)

	if u.Query != "" {
		buf.WriteRune('?')
		buf.WriteString(u.Query)
	}

	if u.Fragment != "" {
		buf.WriteRune('#')
		buf.WriteString(u.Fragment)
	}

	return buf.String()
}

func GetRawScheme(u *RawURL) string {
	if u.Scheme == "" {
		return ""
	}
	var buf strings.Builder
	buf.WriteString(u.Scheme)
	buf.WriteString("://")
	return buf.String()
}

func GetRawUserInfo(u *RawURL) string {
	if u.User == nil {
		return ""
	}
	var buf strings.Builder
	buf.WriteString(u.User.username)
	if u.User.passwordSet {
		buf.WriteRune(':')
		buf.WriteString(u.User.password)
	}
	buf.WriteRune('@')
	return buf.String()
}

func GetRawAuthority(u *RawURL) string {
	var buf strings.Builder
	if u.User != nil {
		buf.WriteString(GetRawUserInfo(u))
	}
	buf.WriteString(u.Host)
	return buf.String()
}

func GetRawHost(u *RawURL) string {
	var buf strings.Builder
	buf.WriteString(u.Host)
	return buf.String()
}

func IsIP(input string) bool {
	if strings.Contains(input, ":") && strings.Count(input, ":") == 1 {
		input, _, _ = net.SplitHostPort(input)
	}
	ip := net.ParseIP(input)
	if ip == nil {
		return false
	}
	return true
}

func (u *RawURL) Subdomain(index ...int) string {
	var i int
	if len(index) > 0 {
		i = index[0]
	}
	if IsIP(u.Hostname()) {
		return ""
	}
	parts := strings.Split(u.Hostname(), ".")
	if len(parts) >= 3 {
		return parts[i]
	}
	return ""
}

func (u *RawURL) GetHostname() string {
	host := u.Host
	if strings.HasPrefix(host, "[") {
		if closeBracket := strings.LastIndex(host, "]"); closeBracket != -1 {
			if len(host) > closeBracket+1 && host[closeBracket+1] == ':' {
				return host[:closeBracket+1]
			}
			return host
		}
		return host
	}
	if i := strings.LastIndex(host, ":"); i != -1 {
		return host[:i]
	}
	return host
}

func (u *RawURL) GetPort() string {
	host := u.Host

	if strings.HasPrefix(host, "[") {
		if closeBracket := strings.LastIndex(host, "]"); closeBracket != -1 {
			if len(host) > closeBracket+1 && host[closeBracket+1] == ':' {
				return host[closeBracket+2:]
			}
			return ""
		}
		return ""
	}

	if i := strings.LastIndex(host, ":"); i != -1 {
		port := host[i+1:]

		for _, b := range port {
			if b < '0' || b > '9' {
				return ""
			}
		}
		return port
	}
	return ""
}

func GetRawPath(u *RawURL) string {
	var buf strings.Builder
	if u.Path == "" {
		buf.WriteString("/")
		return buf.String()
	}

	if len(u.Path) > 0 && u.Path[0] != '/' {
		buf.WriteString("/")
	}
	buf.WriteString(u.Path)
	return buf.String()
}

func GetRawPathUnsafe(u *RawURL) string {
	if u.Path == "" {
		return ""
	}

	var buf strings.Builder

	if len(u.Path) > 0 {
		if u.Path[0] == '/' {
			buf.WriteString(u.Path[1:])
		} else {
			buf.WriteString(u.Path)
		}
	}
	return buf.String()
}

func GetRawQuery(u *RawURL) string {
	if u.Query == "" {
		return ""
	}
	var buf strings.Builder
	buf.WriteRune('?')
	buf.WriteString(u.Query)
	return buf.String()
}

func GetRawFragment(u *RawURL) string {
	if u.Fragment == "" {
		return ""
	}
	var buf strings.Builder
	buf.WriteRune('#')
	buf.WriteString(u.Fragment)
	return buf.String()
}

func (u *RawURL) GetQueryValues() map[string][]string {
	values := make(map[string][]string)
	for _, pair := range strings.Split(u.Query, "&") {
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		key := kv[0]
		value := ""
		if len(kv) == 2 {
			value = kv[1]
		}
		values[key] = append(values[key], value)
	}
	return values
}

/*
GetRawFullURL reconstructs the full URL from its components

--->  scheme://host/path?query#fragment

	             userinfo      host      port    path		       query		            fragment
	            |------| |-------------| |--||---------------| |-------------------------| |-----------|
		https://john.doe@www.example.com:8092/forum/questions/?tag=networking&order=newest#fragmentation
		|----|  |---------------------------|
		scheme         authority
*/
func (u *RawURL) GetRawFullURL() string {
	var buf strings.Builder

	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteString("://")
	}

	buf.WriteString(GetRawAuthority(u))

	buf.WriteString(GetRawPath(u))

	if u.Query != "" {
		buf.WriteRune('?')
		buf.WriteString(u.Query)
	}

	if u.Fragment != "" {
		buf.WriteRune('#')
		buf.WriteString(u.Fragment)
	}

	return buf.String()
}

func (u *RawURL) GetRawRequestURI() string {
	if u.RawRequestURI != "" {
		return u.RawRequestURI
	}

	var buf strings.Builder

	if u.Path != "" {
		buf.WriteString(u.Path)
	}

	if u.Query != "" {
		buf.WriteRune('?')
		buf.WriteString(u.Query)
	}

	if u.Fragment != "" {
		buf.WriteRune('#')
		buf.WriteString(u.Fragment)
	}

	return buf.String()
}

func (u *RawURL) GetRawAbsoluteURI() string {
	var buf strings.Builder

	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteString("://")
	}

	buf.WriteString(GetRawAuthority(u))
	buf.WriteString(u.GetRawRequestURI())

	return buf.String()
}

func (u *RawURL) UpdateRawURL(component URLComponent, newValue string) {
	switch component {
	case Scheme:
		u.Scheme = newValue
	case Username:
		if u.User == nil {
			u.User = &Userinfo{}
		}
		u.User.username = newValue
	case Password:
		if u.User == nil {
			u.User = &Userinfo{}
		}
		u.User.password = newValue
		u.User.passwordSet = true
	case Host:

		if port := u.GetPort(); port != "" {
			u.Host = newValue + ":" + port
		} else {
			u.Host = newValue
		}
	case Port:

		hostname := u.GetHostname()
		if newValue != "" {
			u.Host = hostname + ":" + newValue
		} else {
			u.Host = hostname
		}
	case Path:
		u.Path = newValue
		u.RawRequestURI = ""
	case Query:
		u.Query = newValue
		u.RawRequestURI = ""
	case Fragment:
		u.Fragment = newValue
		u.RawRequestURI = ""
	case RawURI:
		u.RawRequestURI = newValue
	}
}

func (u *RawURL) SetRawRequestURI(uri string) {
	u.UpdateRawURL(RawURI, uri)
}

func splitHostPort(hostPort string) (host, port string) {
	host = hostPort
	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return
}

func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func GetAsciiHex(r rune) string {
	val := strconv.FormatInt(int64(r), 16)
	if len(val) == 1 {

		val = "0" + val
	}
	return strings.ToUpper(val)
}

func GetUTF8Hex(r rune) string {
	var buff bytes.Buffer
	utfchar := string(r)
	hexencstr := hex.EncodeToString([]byte(utfchar))
	for k, v := range hexencstr {
		if k != 0 && k%2 == 0 {
			buff.WriteRune('%')
		}
		buff.WriteRune(v)
	}
	return buff.String()
}

func lastIndexRune(s string, r rune) int {
	if r < utf8.RuneSelf {
		return strings.LastIndex(s, string(r))
	}
	for i := len(s); i > 0; {
		r1, size := utf8.DecodeLastRuneInString(s[:i])
		if r1 == r {
			return i - size
		}
		i -= size
	}
	return -1
}

func GetRuneMap(runes []rune) map[rune]struct{} {
	x := map[rune]struct{}{}
	for _, v := range runes {
		x[v] = struct{}{}
	}
	return x
}
