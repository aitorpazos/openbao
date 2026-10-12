// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/openbao/openbao/sdk/v2/logical"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type EventFilter func(*logical.EventReceived, string) bool
type eventFilterToken struct {
	text   string
	quoted bool
}
type eventFilterParser struct {
	tokens []eventFilterToken
	pos    int
}

// ParseEventFilter implements the public filtering grammar; regexes are compiled
// once, before registration. Input and nesting are bounded to protect the server.
func ParseEventFilter(input string) (EventFilter, error) {
	if len(input) > 16384 {
		return nil, fmt.Errorf("filter too long")
	}
	var tokens []eventFilterToken
	for i := 0; i < len(input); {
		if unicode.IsSpace(rune(input[i])) {
			i++
			continue
		}
		start := i
		ch := input[i]
		if ch == '"' || ch == '`' {
			i++
			for i < len(input) && input[i] != ch {
				if ch == '"' && input[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(input) {
				return nil, fmt.Errorf("unterminated string")
			}
			i++
			text := input[start+1 : i-1]
			if ch == '"' {
				var err error
				text, err = strconv.Unquote(input[start:i])
				if err != nil {
					return nil, err
				}
			}
			tokens = append(tokens, eventFilterToken{text, true})
			continue
		}
		if strings.ContainsRune("()", rune(ch)) {
			i++
		} else if ch == '=' || ch == '!' {
			i++
			if i < len(input) && input[i] == '=' {
				i++
			}
		} else {
			for i < len(input) && !unicode.IsSpace(rune(input[i])) && !strings.ContainsRune("()=!", rune(input[i])) {
				i++
			}
		}
		tokens = append(tokens, eventFilterToken{text: input[start:i]})
	}
	if len(tokens) == 0 {
		return func(*logical.EventReceived, string) bool { return true }, nil
	}
	if len(tokens) > 512 {
		return nil, fmt.Errorf("filter too complex")
	}
	p := &eventFilterParser{tokens: tokens}
	f, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(tokens) {
		return nil, fmt.Errorf("unexpected token %q", p.tokens[p.pos].text)
	}
	return f, nil
}
func (p *eventFilterParser) take(s string) bool {
	if p.pos < len(p.tokens) && !p.tokens[p.pos].quoted && p.tokens[p.pos].text == s {
		p.pos++
		return true
	}
	return false
}
func (p *eventFilterParser) or() (EventFilter, error) {
	a, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.take("or") {
		b, e := p.and()
		if e != nil {
			return nil, e
		}
		left := a
		a = func(v *logical.EventReceived, n string) bool { return left(v, n) || b(v, n) }
	}
	return a, nil
}
func (p *eventFilterParser) and() (EventFilter, error) {
	a, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.take("and") {
		b, e := p.unary()
		if e != nil {
			return nil, e
		}
		left := a
		a = func(v *logical.EventReceived, n string) bool { return left(v, n) && b(v, n) }
	}
	return a, nil
}
func (p *eventFilterParser) unary() (EventFilter, error) {
	if p.take("not") {
		f, e := p.unary()
		if e != nil {
			return nil, e
		}
		return func(v *logical.EventReceived, n string) bool { return !f(v, n) }, nil
	}
	if p.take("(") {
		f, e := p.or()
		if e != nil {
			return nil, e
		}
		if !p.take(")") {
			return nil, fmt.Errorf("expected closing parenthesis")
		}
		return f, nil
	}
	if p.pos >= len(p.tokens) {
		return nil, fmt.Errorf("expected selector")
	}
	sel := p.tokens[p.pos].text
	p.pos++
	sel = strings.TrimPrefix(sel, "/")
	switch sel {
	case "event_type", "operation", "source_plugin_mount", "data_path", "namespace":
	default:
		return nil, fmt.Errorf("unknown event selector %q", sel)
	}
	negate := false
	op := ""
	if p.take("is") {
		negate = p.take("not")
		if !p.take("empty") {
			return nil, fmt.Errorf("expected empty")
		}
		op = "empty"
	} else {
		negate = p.take("not")
		for _, candidate := range []string{"==", "!=", "in", "contains", "matches"} {
			if p.take(candidate) {
				op = candidate
				break
			}
		}
		if op == "" {
			return nil, fmt.Errorf("expected comparison operator")
		}
		if negate && (op == "==" || op == "!=") {
			return nil, fmt.Errorf("invalid negated operator")
		}
	}
	value := ""
	var re *regexp.Regexp
	if op != "empty" {
		if p.pos >= len(p.tokens) {
			return nil, fmt.Errorf("expected value")
		}
		t := p.tokens[p.pos]
		p.pos++
		if !t.quoted && (t.text == "(" || t.text == ")" || t.text == "and" || t.text == "or") {
			return nil, fmt.Errorf("expected literal")
		}
		value = t.text
	}
	if op == "matches" {
		var err error
		re, err = regexp.Compile(value)
		if err != nil {
			return nil, err
		}
	}
	return func(e *logical.EventReceived, ns string) bool {
		actual := ""
		switch sel {
		case "event_type":
			actual = e.GetData().GetEventType()
		case "namespace":
			actual = ns
		case "source_plugin_mount":
			actual = e.GetData().GetPluginInfo().GetMountPath()
		default:
			actual = e.GetData().GetEvent().GetMetadata()[sel]
		}
		result := false
		switch op {
		case "==":
			result = actual == value
		case "!=":
			result = actual != value
		case "empty":
			result = actual == ""
		case "contains":
			result = strings.Contains(actual, value)
		case "in":
			result = strings.Contains(value, actual)
		case "matches":
			result = re.MatchString(actual)
		}
		if negate {
			return !result
		}
		return result
	}, nil
}

// EventTypeMatches treats only '*' as special, including across slashes.
func EventTypeMatches(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(value, part)
		if i < 0 {
			return false
		}
		value = value[i+len(part):]
	}
	return strings.HasSuffix(value, parts[len(parts)-1])
}
