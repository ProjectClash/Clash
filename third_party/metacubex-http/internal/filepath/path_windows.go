//go:build !go1.23 && windows

package filepath

import (
	"strings"
	"syscall"
)

func localize(path string) (string, error) {
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case ':', '\\', 0:
			return "", errInvalidPath
		}
	}
	containsSlash := false
	for p := path; p != ""; {
		var element string
		i := strings.IndexByte(p, '/')
		if i < 0 {
			element = p
			p = ""
		} else {
			containsSlash = true
			element = p[:i]
			p = p[i+1:]
		}
		if isReservedName(element) {
			return "", errInvalidPath
		}
	}
	if containsSlash {
		buf := []byte(path)
		for i, b := range buf {
			if b == '/' {
				buf[i] = '\\'
			}
		}
		path = string(buf)
	}
	return path, nil
}

func isReservedName(name string) bool {
	base := name
	for i := 0; i < len(base); i++ {
		switch base[i] {
		case ':', '.':
			base = base[:i]
		}
	}
	for len(base) > 0 && base[len(base)-1] == ' ' {
		base = base[:len(base)-1]
	}
	if !isReservedBaseName(base) {
		return false
	}
	if len(base) == len(name) {
		return true
	}
	if p, _ := syscall.FullPath(name); len(p) >= 4 && p[:4] == `\\.\` {
		return true
	}
	return false
}

func isReservedBaseName(name string) bool {
	if len(name) == 3 {
		switch string([]byte{toUpper(name[0]), toUpper(name[1]), toUpper(name[2])}) {
		case "CON", "PRN", "AUX", "NUL":
			return true
		}
	}
	if len(name) >= 4 {
		switch string([]byte{toUpper(name[0]), toUpper(name[1]), toUpper(name[2])}) {
		case "COM", "LPT":
			if len(name) == 4 && '1' <= name[3] && name[3] <= '9' {
				return true
			}
			switch name[3:] {
			case "\u00b2", "\u00b3", "\u00b9":
				return true
			}
			return false
		}
	}

	if len(name) == 6 && name[5] == '$' && equalFold(name, "CONIN$") {
		return true
	}
	if len(name) == 7 && name[6] == '$' && equalFold(name, "CONOUT$") {
		return true
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if toUpper(a[i]) != toUpper(b[i]) {
			return false
		}
	}
	return true
}

func toUpper(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}
