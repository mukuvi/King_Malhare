package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Meta struct {
	Name          string                 `json:"name"`
	Label         string                 `json:"label"`
	Category      string                 `json:"category"`
	Description   string                 `json:"description"`
	Intrusive     bool                   `json:"intrusive"`
	Binary        string                 `json:"binary,omitempty"`
	Params        map[string]ParamSchema `json:"params"`
	DefaultParams map[string]any         `json:"default_params"`
}

type ParamSchema struct {
	Type        string   `json:"type"`
	Enum        []string `json:"enum,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	MaxItems    int      `json:"max_items,omitempty"`
	Description string   `json:"description"`
}

var Catalog = []Meta{
	{
		Name: "http-baseline", Label: "HTTP baseline", Category: "web", Binary: "",
		Description: "Non-intrusive checks for security headers, cookies, CORS, TLS, disclosure and exposed paths.",
		Params: map[string]ParamSchema{
			"exposure_check": {Type: "bool", Description: "Check common sensitive paths"},
			"tls_check":      {Type: "bool", Description: "Inspect TLS certificate and protocol"},
			"cors_check":     {Type: "bool", Description: "Test cross-origin behaviour"},
			"max_requests":   {Type: "int", Min: ptr(10), Max: ptr(300), Description: "Hard request budget"},
		},
		DefaultParams: map[string]any{"exposure_check": true, "tls_check": true, "cors_check": true, "max_requests": 120},
	},
	{
		Name: "nmap", Label: "Nmap", Category: "network", Binary: "nmap",
		Description: "Host discovery, port scanning, service/version detection and risky service identification.",
		Params: map[string]ParamSchema{
			"ports":             {Type: "enum", Enum: []string{"top-100", "top-1000", "all"}, Description: "Port set"},
			"service_detection": {Type: "bool", Description: "Run -sV version detection"},
			"os_detection":      {Type: "bool", Description: "Run -O fingerprinting (requires privileges)"},
			"host_discovery":    {Type: "bool", Description: "Ping discovery before scanning"},
		},
		DefaultParams: map[string]any{"ports": "top-1000", "service_detection": true, "os_detection": false, "host_discovery": true},
	},
	{
		Name: "nuclei", Label: "Nuclei", Category: "web", Binary: "nuclei",
		Description: "Template-based vulnerability and exposure detection with structured JSONL output.",
		Params: map[string]ParamSchema{
			"severity":   {Type: "string_list", Enum: []string{"info", "low", "medium", "high", "critical"}, MaxItems: 5, Description: "Severities to include"},
			"tags":       {Type: "string_list", Enum: []string{"cve", "exposure", "misconfig", "panel", "tech", "default-login", "takeover", "xss", "sqli"}, MaxItems: 8, Description: "Template tags"},
			"rate_limit": {Type: "int", Min: ptr(1), Max: ptr(150), Description: "Requests per second"},
			"timeout":    {Type: "int", Min: ptr(3), Max: ptr(60), Description: "Per-request timeout in seconds"},
		},
		DefaultParams: map[string]any{"severity": []string{"medium", "high", "critical"}, "rate_limit": 40, "timeout": 10},
	},
	{
		Name: "zap", Label: "OWASP ZAP", Category: "web", Binary: "",
		Description: "Spider and passive analysis; active scanning requires intrusive approval and a configured ZAP daemon.",
		Params: map[string]ParamSchema{
			"mode":                 {Type: "enum", Enum: []string{"spider", "active"}, Description: "Scan mode"},
			"max_duration_minutes": {Type: "int", Min: ptr(1), Max: ptr(30), Description: "Time budget"},
		},
		DefaultParams: map[string]any{"mode": "spider", "max_duration_minutes": 5},
	},
	{
		Name: "nikto", Label: "Nikto", Category: "web", Binary: "nikto",
		Description: "Web server misconfiguration and dangerous file checks.",
		Params: map[string]ParamSchema{
			"max_time": {Type: "enum", Enum: []string{"2m", "5m", "10m"}, Description: "Time budget"},
		},
		DefaultParams: map[string]any{"max_time": "5m"},
	},
	{
		Name: "gobuster", Label: "Gobuster", Category: "web", Binary: "gobuster",
		Description: "Bounded content discovery against a curated wordlist.",
		Params: map[string]ParamSchema{
			"wordlist":   {Type: "enum", Enum: []string{"common", "small"}, Description: "Wordlist preset"},
			"threads":    {Type: "int", Min: ptr(1), Max: ptr(20), Description: "Concurrency"},
			"extensions": {Type: "string_list", Enum: []string{"php", "asp", "aspx", "jsp", "json", "bak", "old", "txt"}, MaxItems: 8, Description: "Extensions"},
		},
		DefaultParams: map[string]any{"wordlist": "common", "threads": 10},
	},
	{
		Name: "testssl", Label: "testssl.sh", Category: "network", Binary: "testssl.sh",
		Description: "TLS protocol, cipher and certificate assessment.",
		Params: map[string]ParamSchema{
			"protocols": {Type: "bool", Description: "Include protocol tests"},
		},
		DefaultParams: map[string]any{"protocols": true},
	},
	{
		Name: "sqlmap", Label: "SQLMap", Category: "web", Binary: "sqlmap", Intrusive: true,
		Description: "Guarded SQL injection verification on one parameter. Requires intrusive approval. No shell or data dump.",
		Params: map[string]ParamSchema{
			"level":     {Type: "int", Min: ptr(1), Max: ptr(2), Description: "Test level (max 2)"},
			"risk":      {Type: "int", Min: ptr(1), Max: ptr(2), Description: "Risk (max 2)"},
			"technique": {Type: "enum", Enum: []string{"B", "E", "BE"}, Description: "Boolean / error techniques only"},
		},
		DefaultParams: map[string]any{"level": 1, "risk": 1, "technique": "B"},
	},
	{
		Name: "trivy", Label: "Trivy", Category: "infrastructure", Binary: "trivy",
		Description: "Container image and filesystem vulnerability / misconfiguration scan.",
		Params: map[string]ParamSchema{
			"scan_type": {Type: "enum", Enum: []string{"image", "fs"}, Description: "Scan target kind"},
			"severity":  {Type: "string_list", Enum: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}, MaxItems: 4, Description: "Severities"},
		},
		DefaultParams: map[string]any{"scan_type": "image", "severity": []string{"CRITICAL", "HIGH", "MEDIUM"}},
	},
	{
		Name: "prowler", Label: "Prowler", Category: "cloud", Binary: "prowler",
		Description: "Read-only multi-cloud posture assessment via the Prowler CLI.",
		Params: map[string]ParamSchema{
			"provider": {Type: "enum", Enum: []string{"aws", "azure", "gcp"}, Description: "Cloud provider"},
			"severity": {Type: "string_list", Enum: []string{"critical", "high", "medium", "low"}, MaxItems: 4, Description: "Severities"},
		},
		DefaultParams: map[string]any{"provider": "aws", "severity": []string{"critical", "high", "medium"}},
	},
	{
		Name: "scoutsuite", Label: "ScoutSuite", Category: "cloud", Binary: "scoutsuite",
		Description: "Read-only cloud configuration assessment via ScoutSuite.",
		Params: map[string]ParamSchema{
			"provider": {Type: "enum", Enum: []string{"aws", "azure", "gcp"}, Description: "Cloud provider"},
		},
		DefaultParams: map[string]any{"provider": "aws"},
	},
	{
		Name: "checkov", Label: "Checkov", Category: "infrastructure", Binary: "checkov",
		Description: "Static IaC misconfiguration analysis for an allowlisted repository path.",
		Params: map[string]ParamSchema{
			"framework": {Type: "enum", Enum: []string{"all", "terraform", "kubernetes", "dockerfile", "cloudformation"}, Description: "Framework"},
			"scan_path": {Type: "string", Description: "Absolute path inside CHECKOV_ALLOWED_ROOT (optional; defaults to the asset target)"},
		},
		DefaultParams: map[string]any{"framework": "all"},
	},
	{
		Name: "aws-posture", Label: "AWS posture", Category: "cloud", Binary: "",
		Description: "Native read-only AWS checks using STS/s3/cloudtrail/iam/ec2 APIs.",
		Params: map[string]ParamSchema{
			"regions": {Type: "string_list", Enum: []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1", "ap-southeast-1"}, MaxItems: 4, Description: "Regions"},
			"checks":  {Type: "string_list", Enum: []string{"root_mfa", "cloudtrail", "s3_public_access", "password_policy", "open_security_groups", "stale_keys"}, MaxItems: 6, Description: "Check selection"},
		},
		DefaultParams: map[string]any{"regions": []string{"us-east-1"}, "checks": []string{"root_mfa", "cloudtrail", "s3_public_access", "password_policy", "open_security_groups", "stale_keys"}},
	},
	{
		Name: "auth-baseline", Label: "Auth baseline", Category: "authentication", Binary: "", Intrusive: true,
		Description: "Rate-limit, lockout and session checks against an explicitly authorized test account. Requires intrusive approval.",
		Params: map[string]ParamSchema{
			"login_path":     {Type: "path", Description: "Login endpoint path (e.g. /api/auth/login)"},
			"username_field": {Type: "field", Description: "Username field name"},
			"password_field": {Type: "field", Description: "Password field name"},
			"request_format": {Type: "enum", Enum: []string{"json", "form"}, Description: "Request encoding"},
			"test_username":  {Type: "string", Description: "Explicitly authorized test account username"},
			"attempts":       {Type: "int", Min: ptr(1), Max: ptr(10), Description: "Wrong-password attempts"},
			"delay_ms":       {Type: "int", Min: ptr(100), Max: ptr(5000), Description: "Delay between attempts"},
		},
		DefaultParams: map[string]any{"login_path": "/login", "username_field": "username", "password_field": "password", "attempts": 5, "delay_ms": 500},
	},
}

func ptr(f float64) *float64 { return &f }

func Find(name string) (Meta, bool) {
	for _, m := range Catalog {
		if m.Name == name {
			return m, true
		}
	}
	return Meta{}, false
}

func IsIntrusive(scanner string, config map[string]any) bool {
	m, ok := Find(scanner)
	if !ok {
		return true
	}
	if m.Intrusive {
		return true
	}
	if scanner == "zap" {
		if mode, _ := config["mode"].(string); mode == "active" {
			return true
		}
	}
	return false
}

var (
	ErrInvalidTarget   = errors.New("invalid target")
	ErrPrivateTarget   = errors.New("private target requires an authorization that explicitly allows internal systems")
	ErrMetadataTarget  = errors.New("targets resolving to cloud metadata endpoints are blocked")
	ErrUnresolved      = errors.New("target could not be resolved")
	ErrUnsupportedType = errors.New("unsupported asset type for this scanner")
)

var metadataHosts = map[string]bool{
	"metadata.google.internal":   true,
	"metadata.goog":              true,
	"metadata":                   true,
	"instance-data":              true,
	"instance-data.ec2.internal": true,
}

var metadataIPs = []string{
	"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254",
}

var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$`)

func isMetadataIP(ip net.IP) bool {
	for _, s := range metadataIPs {
		if m := net.ParseIP(s); m != nil && m.Equal(ip) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 { // 100.64.0.0/10 CGNAT
			return true
		}
	}
	return false
}

// NormalizeTarget validates the target syntax and returns a canonical form.
func NormalizeTarget(assetType, target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 2048 {
		return "", ErrInvalidTarget
	}
	if strings.ContainsAny(target, "\n\r\t\x00") {
		return "", ErrInvalidTarget
	}
	switch assetType {
	case "website", "web_app", "api", "graphql_api":
		if !strings.Contains(target, "://") {
			target = "https://" + target
		}
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", ErrInvalidTarget
		}
		if u.User != nil {
			return "", fmt.Errorf("%w: credentials in URLs are not allowed", ErrInvalidTarget)
		}
		u.Fragment = ""
		host := u.Hostname()
		if metadataHosts[strings.ToLower(host)] {
			return "", ErrMetadataTarget
		}
		if ip := net.ParseIP(host); ip != nil && isMetadataIP(ip) {
			return "", ErrMetadataTarget
		}
		return u.String(), nil
	case "ip":
		ip := net.ParseIP(target)
		if ip == nil {
			return "", ErrInvalidTarget
		}
		if isMetadataIP(ip) {
			return "", ErrMetadataTarget
		}
		return ip.String(), nil
	case "network":
		if _, cidr, err := net.ParseCIDR(target); err == nil {
			if ones, bits := cidr.Mask.Size(); bits-ones > 16 {
				return "", fmt.Errorf("%w: network range larger than /16 is not allowed", ErrInvalidTarget)
			}
			for _, m := range metadataIPs {
				if ip := net.ParseIP(m); ip != nil && cidr.Contains(ip) {
					return "", ErrMetadataTarget
				}
			}
			return cidr.String(), nil
		}
		ip := net.ParseIP(target)
		if ip == nil {
			return "", ErrInvalidTarget
		}
		if isMetadataIP(ip) {
			return "", ErrMetadataTarget
		}
		return ip.String(), nil
	case "server", "internal":
		host := target
		if strings.Contains(target, "://") {
			u, err := url.Parse(target)
			if err != nil || u.Hostname() == "" {
				return "", ErrInvalidTarget
			}
			host = u.Hostname()
		} else if h, _, err := net.SplitHostPort(target); err == nil {
			host = h
		}
		if host == "" || (net.ParseIP(host) == nil && !hostnameRe.MatchString(host)) {
			return "", ErrInvalidTarget
		}
		if metadataHosts[strings.ToLower(host)] {
			return "", ErrMetadataTarget
		}
		return target, nil
	case "cloud":
		if !regexp.MustCompile(`^[A-Za-z0-9_\-:/\.]{2,240}$`).MatchString(target) {
			return "", ErrInvalidTarget
		}
		return target, nil
	case "container":
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]{1,300}$`).MatchString(target) {
			return "", ErrInvalidTarget
		}
		return target, nil
	default:
		return "", ErrUnsupportedType
	}
}

// ResolveAndAuthorize resolves a target and enforces metadata/private-range policy.
func ResolveAndAuthorize(ctx context.Context, assetType, target string, allowPrivate bool) ([]net.IP, error) {
	host := target
	switch assetType {
	case "website", "web_app", "api", "graphql_api":
		u, err := url.Parse(target)
		if err != nil {
			return nil, ErrInvalidTarget
		}
		host = u.Hostname()
	case "ip", "network":
		if _, cidr, err := net.ParseCIDR(target); err == nil {
			if err := ValidateNetworkPolicy(target, allowPrivate); err != nil {
				return nil, err
			}
			_ = cidr
			return nil, nil
		}
		host = target
	case "server", "internal":
		if h, _, err := net.SplitHostPort(target); err == nil {
			host = h
		}
		host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return nil, ErrInvalidTarget
	}
	if metadataHosts[strings.ToLower(host)] {
		return nil, ErrMetadataTarget
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		if !hostnameRe.MatchString(host) {
			return nil, ErrInvalidTarget
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
		if err != nil || len(addrs) == 0 {
			return nil, ErrUnresolved
		}
		ips = addrs
	}
	for _, ip := range ips {
		if isMetadataIP(ip) {
			return nil, ErrMetadataTarget
		}
		if isPrivateIP(ip) && !allowPrivate {
			return nil, ErrPrivateTarget
		}
	}
	return ips, nil
}

// ValidateNetworkPolicy enforces CIDR size, metadata and private-range rules.
func ValidateNetworkPolicy(target string, allowPrivate bool) error {
	ip := net.ParseIP(target)
	if ip == nil {
		cidrIP, cidr, err := net.ParseCIDR(target)
		if err != nil {
			return ErrInvalidTarget
		}
		_ = cidrIP
		if ones, bits := cidr.Mask.Size(); bits-ones > 16 {
			return fmt.Errorf("%w: network range larger than /16 is not allowed", ErrInvalidTarget)
		}
		for _, m := range metadataIPs {
			if mip := net.ParseIP(m); mip != nil && cidr.Contains(mip) {
				return ErrMetadataTarget
			}
		}
		if (cidr.IP.IsPrivate() || cidr.IP.IsLoopback() || cidr.IP.IsLinkLocalUnicast()) && !allowPrivate {
			return ErrPrivateTarget
		}
		for _, blocked := range []string{"169.254.0.0/16", "fe80::/10"} {
			if _, bnet, err := net.ParseCIDR(blocked); err == nil {
				if cidr.Contains(bnet.IP) || bnet.Contains(cidr.IP) {
					return ErrMetadataTarget
				}
			}
		}
		return nil
	}
	if isMetadataIP(ip) {
		return ErrMetadataTarget
	}
	if isPrivateIP(ip) && !allowPrivate {
		return ErrPrivateTarget
	}
	return nil
}

// ValidateParams strictly validates scanner parameters against the catalog and merges defaults.
func ValidateParams(scannerName string, in map[string]any) (map[string]any, error) {
	meta, ok := Find(scannerName)
	if !ok {
		return nil, fmt.Errorf("unknown scanner %q", scannerName)
	}
	out := map[string]any{}
	for k, v := range meta.DefaultParams {
		out[k] = v
	}
	for k, v := range in {
		schema, ok := meta.Params[k]
		if !ok {
			return nil, fmt.Errorf("parameter %q is not allowed for scanner %q", k, scannerName)
		}
		if err := validateParam(k, schema, v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

func validateParam(key string, s ParamSchema, v any) error {
	switch s.Type {
	case "bool":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", key)
		}
	case "int":
		f, ok := numeric(v)
		if !ok {
			return fmt.Errorf("%s must be a number", key)
		}
		if s.Min != nil && f < *s.Min {
			return fmt.Errorf("%s is below the minimum %v", key, *s.Min)
		}
		if s.Max != nil && f > *s.Max {
			return fmt.Errorf("%s exceeds the maximum %v", key, *s.Max)
		}
	case "enum":
		str, ok := v.(string)
		if !ok || !contains(s.Enum, str) {
			return fmt.Errorf("%s must be one of %v", key, s.Enum)
		}
	case "string_list", "string":
		if s.Type == "string" {
			str, ok := v.(string)
			if !ok || len(str) < 1 || len(str) > 300 {
				return fmt.Errorf("%s must be a non-empty string", key)
			}
			if strings.ContainsAny(str, "\x00\n\r") {
				return fmt.Errorf("%s contains invalid characters", key)
			}
			return nil
		}
		list, ok := toStringSlice(v)
		if !ok {
			return fmt.Errorf("%s must be a list of strings", key)
		}
		if s.MaxItems > 0 && len(list) > s.MaxItems {
			return fmt.Errorf("%s accepts at most %d entries", key, s.MaxItems)
		}
		for _, item := range list {
			if s.Enum != nil && !contains(s.Enum, item) {
				return fmt.Errorf("%s contains invalid value %q", key, item)
			}
		}
	case "path":
		str, ok := v.(string)
		if !ok || !strings.HasPrefix(str, "/") || len(str) > 200 || strings.ContainsAny(str, " \t\n\r?#") {
			return fmt.Errorf("%s must be a clean absolute path", key)
		}
	case "field":
		str, ok := v.(string)
		if !ok || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_\-\.]{0,60}$`).MatchString(str) {
			return fmt.Errorf("%s is not a valid form field name", key)
		}
	default:
		return fmt.Errorf("unsupported schema for %s", key)
	}
	return nil
}

func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func toStringSlice(v any) ([]string, bool) {
	switch list := v.(type) {
	case []string:
		return list, true
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
