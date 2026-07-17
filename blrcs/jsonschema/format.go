package jsonschema

import (
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// checkFormat performs lenient validation of the JSON Schema `format` keyword.
// Unknown formats pass (per spec, `format` is an annotation by default).
func checkFormat(format, s string) bool {
	switch format {
	case "date-time":
		_, err := time.Parse(time.RFC3339, s)
		return err == nil
	case "date":
		_, err := time.Parse("2006-01-02", s)
		return err == nil
	case "time":
		_, err := time.Parse("15:04:05Z07:00", s)
		if err == nil {
			return true
		}
		_, err = time.Parse("15:04:05", s)
		return err == nil
	case "email":
		_, err := mail.ParseAddress(s)
		return err == nil
	case "uri":
		u, err := url.Parse(s)
		return err == nil && u.IsAbs()
	case "uri-reference":
		_, err := url.Parse(s)
		return err == nil
	case "hostname":
		return isHostname(s)
	case "ipv4":
		return isIPv4(s)
	case "uuid":
		return isUUID(s)
	default:
		// Unknown format: treat as a passing annotation.
		return true
	}
}

func isHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
			n = n*10 + int(p[i]-'0')
		}
		if n > 255 || (len(p) > 1 && p[0] == '0') {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
