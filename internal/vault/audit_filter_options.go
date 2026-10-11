// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/scanner"

	"github.com/openbao/openbao/v2/internal/vault/routing"
)

// validateAuditFilterOptions validates enable-time configuration while auditLock
// is held, making fallback uniqueness atomic with device creation. Options are
// persisted and returned by the existing audit mount table. This is configuration
// support only: broker routing and emitted-record exclusion are not implemented.
func validateAuditFilterOptions(entry *routing.MountEntry, existing []*routing.MountEntry) error {
	options := entry.Options
	fallback := false
	if raw, ok := options["fallback"]; ok {
		var err error
		fallback, err = strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("invalid fallback: %w", err)
		}
	}
	if fallback || options["filter"] != "" || options["exclude"] != "" {
		switch entry.Type {
		case "file", "socket", "syslog":
		default:
			return fmt.Errorf("audit filtering requires file, socket, or syslog")
		}
	}
	if fallback {
		for _, device := range existing {
			enabled, _ := strconv.ParseBool(device.Options["fallback"])
			if enabled {
				return fmt.Errorf("only one fallback audit device is allowed")
			}
		}
	}
	if filter := options["filter"]; filter != "" {
		if err := validateAuditPredicate(filter, false); err != nil {
			return fmt.Errorf("invalid filter: %w", err)
		}
	}
	if raw, ok := options["exclude"]; ok {
		var exclusions []struct {
			Condition string   `json:"condition"`
			Fields    []string `json:"fields"`
		}
		if err := json.Unmarshal([]byte(raw), &exclusions); err != nil {
			return fmt.Errorf("invalid exclude: %w", err)
		}
		if exclusions == nil {
			return fmt.Errorf("exclude must be a JSON array")
		}
		for _, exclusion := range exclusions {
			if len(exclusion.Fields) == 0 {
				return fmt.Errorf("exclude fields must not be empty")
			}
			for _, field := range exclusion.Fields {
				if !validAuditPointer(field) {
					return fmt.Errorf("invalid exclusion field %q", field)
				}
			}
			if exclusion.Condition != "" {
				if err := validateAuditPredicate(exclusion.Condition, true); err != nil {
					return fmt.Errorf("invalid exclusion condition: %w", err)
				}
			}
		}
	}
	return nil
}

func validAuditPointer(s string) bool {
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '~' {
			i++
			if i == len(s) || (s[i] != '0' && s[i] != '1') {
				return false
			}
		}
	}
	return true
}

// auditPredicateParser checks boolean combinations of documented string
// comparisons. It deliberately does not evaluate or mutate audit log records.
type auditPredicateParser struct {
	scanner  scanner.Scanner
	token    rune
	text     string
	pointers bool
	scanErr  error
	depth    int
}

func validateAuditPredicate(expression string, pointers bool) error {
	p := &auditPredicateParser{pointers: pointers}
	p.scanner.Init(strings.NewReader(expression))
	p.scanner.Mode = scanner.ScanIdents | scanner.ScanStrings
	p.scanner.Error = func(_ *scanner.Scanner, msg string) { p.scanErr = fmt.Errorf("%s", msg) }
	p.next()
	if err := p.expression(); err != nil {
		return err
	}
	if p.scanErr != nil {
		return p.scanErr
	}
	if p.token != scanner.EOF {
		return fmt.Errorf("unexpected token %q", p.text)
	}
	return nil
}
func (p *auditPredicateParser) next() { p.token = p.scanner.Scan(); p.text = p.scanner.TokenText() }
func (p *auditPredicateParser) expression() error {
	if err := p.term(); err != nil {
		return err
	}
	for p.text == "and" || p.text == "or" {
		p.next()
		if err := p.term(); err != nil {
			return err
		}
	}
	return nil
}
func (p *auditPredicateParser) term() error {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 64 {
		return fmt.Errorf("predicate nesting exceeds 64")
	}
	if p.text == "not" {
		p.next()
		return p.term()
	}
	if p.token == '(' {
		p.next()
		if err := p.expression(); err != nil {
			return err
		}
		if p.token != ')' {
			return fmt.Errorf("missing closing parenthesis")
		}
		p.next()
		return nil
	}
	field := p.text
	if p.token == scanner.String {
		var err error
		field, err = strconv.Unquote(field)
		if err != nil {
			return err
		}
	} else if p.token != scanner.Ident {
		return fmt.Errorf("expected property")
	}
	if p.pointers {
		if !validAuditPointer(field) {
			return fmt.Errorf("invalid condition field %q", field)
		}
	} else {
		switch field {
		case "mount_point", "mount_type", "namespace", "operation", "path":
		default:
			return fmt.Errorf("unsupported filter property %q", field)
		}
	}
	p.next()
	op := p.text
	switch op {
	case "=", "!":
		p.next()
		if p.token != '=' {
			return fmt.Errorf("expected equality operator")
		}
		op += "="
		p.next()
	case "matches", "contains", "in":
		p.next()
	case "is":
		p.next()
		if p.text == "not" {
			p.next()
		}
		if p.text != "empty" {
			return fmt.Errorf("expected empty")
		}
		p.next()
		return nil
	default:
		return fmt.Errorf("unsupported operator %q", op)
	}
	if p.token != scanner.String && p.token != scanner.Ident {
		return fmt.Errorf("expected string value")
	}
	value := p.text
	if p.token == scanner.String {
		var err error
		value, err = strconv.Unquote(value)
		if err != nil {
			return err
		}
	}
	if op == "matches" {
		if _, err := regexp.Compile(value); err != nil {
			return err
		}
	}
	p.next()
	return nil
}
