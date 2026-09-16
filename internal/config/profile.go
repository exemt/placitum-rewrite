package config

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-rewrite/internal/protocol"
)

const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"
)

const (
	OnResponse = "response"
	OnFrame    = "frame"

	DirectionC2S = "c2s"
	DirectionS2C = "s2c"

	OpcodeText         = "text"
	OpcodeBinary       = "binary"
	OpcodeContinuation = "continuation"
)

const DefaultName = "default"

const ProbeName = "_probe"

const DefaultDenyResponse = "rewrite_failed"

const (
	MaxGroups        = 16
	MaxOpsPerGroup   = 32
	MaxMatchesPerOp  = 4096
	DefaultMaxMatch  = 256
	MatchBudget      = 4096
	MaxPatternLength = 512
)

var nameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,63}$`)

var forbiddenHeader = map[string]bool{
	"host": true, "authorization": true, "cookie": true,
	"content-length": true, "transfer-encoding": true,
	"content-encoding": true, "connection": true, "upgrade": true,
	"keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true,
	"location": true, "date": true,
}

const (
	OpRemove       = "remove"
	OpReplace      = "replace"
	OpInsertBefore = "insert_before"
	OpInsertAfter  = "insert_after"

	OpSet   = "set"
	OpUnset = "unset"
)

type Profile struct {
	Name        string `yaml:"-"`
	Description string `yaml:"description"`
	Mode        string `yaml:"mode"`

	DenyResponse string `yaml:"deny_response"`

	Groups  []*Group `yaml:"groups"`
	Trigger Trigger  `yaml:"trigger"`
}

type Group struct {
	Name string `yaml:"name"`

	Default bool `yaml:"default"`

	On string `yaml:"on"`

	Status      []int    `yaml:"status"`
	ContentType []string `yaml:"content_type"`

	Direction []string `yaml:"direction"`
	Opcode    []string `yaml:"opcode"`

	Body    []*BodyOp  `yaml:"body"`
	Headers []HeaderOp `yaml:"headers"`
}

func (g *Group) OnFrame() bool { return g.On == OnFrame }

func (g *Group) MatchesFrame(direction, opcode string) bool {
	if len(g.Direction) != 0 && !hasFold(g.Direction, direction) {
		return false
	}

	return len(g.Opcode) == 0 || hasFold(g.Opcode, opcode)
}

func hasFold(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(item, want) {
			return true
		}
	}

	return false
}

type BodyOp struct {
	Op      string `yaml:"op"`
	Pattern string `yaml:"pattern"`

	To   string `yaml:"to"`
	Text string `yaml:"text"`

	MaxMatches int `yaml:"max_matches"`

	re *regexp.Regexp
}

func (o *BodyOp) Regexp() *regexp.Regexp { return o.re }

type HeaderOp struct {
	Op    string `yaml:"op"`
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

func (g *Group) Matches(status int, contentType string) bool {
	if len(g.Status) != 0 {
		hit := false

		for _, s := range g.Status {
			if s == status {
				hit = true
				break
			}
		}

		if !hit {
			return false
		}
	}

	return typeAllowed(g.ContentType, contentType)
}

func (g *Group) HasBody() bool { return len(g.Body) != 0 }

func typeAllowed(want []string, contentType string) bool {
	if len(want) == 0 {
		return true
	}

	ct := strings.ToLower(strings.TrimSpace(contentType))

	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}

	for _, w := range want {
		w = strings.ToLower(strings.TrimSpace(w))

		if strings.HasPrefix(w, "+") {
			if strings.HasSuffix(ct, w) {
				return true
			}

			continue
		}

		if ct == w {
			return true
		}
	}

	return false
}

const AnyInspector = "*"

type Trigger struct {
	Prior []PriorRule `yaml:"prior"`
}

const (
	SetOn  = "on"
	SetOff = "off"
)

type PriorRule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	Codes  []string `yaml:"codes"`
}

func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

func (r PriorRule) WantsCode(code string) bool {
	if len(r.Codes) == 0 {
		return true
	}

	for _, c := range r.Codes {
		if c == code {
			return true
		}
	}

	return false
}

func defaults(name string) *Profile {
	return &Profile{
		Name:         name,
		Mode:         ModeEnforce,
		DenyResponse: DefaultDenyResponse,
	}
}

func ParseProfile(name string, raw []byte) (*Profile, error) {
	p := defaults(name)

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	p.Name = name

	return p, nil
}

func (p *Profile) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeObserve, ModeOff:
	default:
		return fmt.Errorf("mode: expected enforce, observe or off, got %q", p.Mode)
	}

	if p.DenyResponse == "" {
		return fmt.Errorf("deny_response is empty")
	}

	if len(p.Groups) > MaxGroups {
		return fmt.Errorf("groups: %d is above the %d limit", len(p.Groups), MaxGroups)
	}

	seen := map[string]bool{}

	for i, g := range p.Groups {
		if g == nil {
			return fmt.Errorf("groups[%d] is empty", i)
		}

		if !nameRe.MatchString(g.Name) {
			return fmt.Errorf("groups[%d]: bad name %q", i, g.Name)
		}

		if seen[g.Name] {
			return fmt.Errorf("groups[%d]: duplicate name %q", i, g.Name)
		}

		seen[g.Name] = true

		if err := g.validate(); err != nil {
			return fmt.Errorf("group %s: %w", g.Name, err)
		}
	}

	for i, r := range p.Trigger.Prior {
		if err := p.validatePrior(i, r); err != nil {
			return err
		}
	}

	return nil
}

func (g *Group) validate() error {
	if len(g.Body)+len(g.Headers) == 0 {
		return fmt.Errorf("no operations: a group must change something")
	}

	if g.On == "" {
		g.On = OnResponse
	}

	switch g.On {
	case OnResponse:
		if len(g.Direction)+len(g.Opcode) != 0 {
			return fmt.Errorf("direction and opcode are frame selectors; set on: frame")
		}

	case OnFrame:
		if len(g.Headers) != 0 {
			return fmt.Errorf("a frame has no headers to change")
		}

		if len(g.Status)+len(g.ContentType) != 0 {
			return fmt.Errorf("status and content_type are response selectors; " +
				"a frame group selects by direction and opcode")
		}

		for _, d := range g.Direction {
			if d != DirectionC2S && d != DirectionS2C {
				return fmt.Errorf("direction: expected %s or %s, got %q",
					DirectionC2S, DirectionS2C, d)
			}
		}

		for _, op := range g.Opcode {
			if op != OpcodeText && op != OpcodeBinary && op != OpcodeContinuation {
				return fmt.Errorf("opcode: expected %s, %s or %s, got %q",
					OpcodeText, OpcodeBinary, OpcodeContinuation, op)
			}
		}

		if len(g.Opcode) == 0 {
			g.Opcode = []string{OpcodeText}
		}

	default:
		return fmt.Errorf("on: expected %s or %s, got %q", OnResponse, OnFrame, g.On)
	}

	if len(g.Body)+len(g.Headers) > MaxOpsPerGroup {
		return fmt.Errorf("%d operations is above the %d limit",
			len(g.Body)+len(g.Headers), MaxOpsPerGroup)
	}

	for _, s := range g.Status {
		if s < 100 || s > 599 {
			return fmt.Errorf("status %d is not an http status", s)
		}
	}

	for i, op := range g.Body {
		if err := op.compile(); err != nil {
			return fmt.Errorf("body[%d]: %w", i, err)
		}
	}

	for i, op := range g.Headers {
		if err := op.validate(); err != nil {
			return fmt.Errorf("headers[%d]: %w", i, err)
		}
	}

	return nil
}

func (o *BodyOp) compile() error {
	switch o.Op {
	case OpRemove, OpReplace, OpInsertBefore, OpInsertAfter:
	default:
		return fmt.Errorf("op: expected remove, replace, insert_before or "+
			"insert_after, got %q", o.Op)
	}

	if o.Pattern == "" {
		return fmt.Errorf("pattern is empty")
	}

	if len(o.Pattern) > MaxPatternLength {
		return fmt.Errorf("pattern is longer than %d bytes", MaxPatternLength)
	}

	re, err := regexp.Compile(o.Pattern)
	if err != nil {
		return fmt.Errorf("pattern: %w", err)
	}

	o.re = re

	if o.Op == OpReplace {
		if o.Text != "" {
			return fmt.Errorf("text is only for insert_*; replace uses to")
		}
	} else if o.To != "" {
		return fmt.Errorf("to is only for replace")
	}

	if (o.Op == OpInsertBefore || o.Op == OpInsertAfter) && o.Text == "" {
		return fmt.Errorf("text is empty")
	}

	if o.MaxMatches == 0 {
		o.MaxMatches = DefaultMaxMatch
	}

	if o.MaxMatches < 0 || o.MaxMatches > MaxMatchesPerOp {
		return fmt.Errorf("max_matches %d is out of 1..%d", o.MaxMatches, MaxMatchesPerOp)
	}

	return nil
}

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

func (o HeaderOp) validate() error {
	switch o.Op {
	case OpSet, OpUnset:
	default:
		return fmt.Errorf("op: expected set or unset, got %q", o.Op)
	}

	if !headerNameRe.MatchString(o.Name) {
		return fmt.Errorf("bad header name %q", o.Name)
	}

	lower := strings.ToLower(o.Name)

	if forbiddenHeader[lower] {
		return fmt.Errorf("header %q is not ours to change", o.Name)
	}

	if o.Op == OpSet && lower == "set-cookie" {
		return fmt.Errorf("set-cookie is set by the cookie channel only")
	}

	if o.Op == OpUnset && lower == "content-type" {
		return fmt.Errorf("a response without a content type is not a thing")
	}

	if o.Op == OpSet {
		if strings.ContainsAny(o.Value, "\r\n\x00") {
			return fmt.Errorf("header %q value has CR, LF or NUL", o.Name)
		}
	} else if o.Value != "" {
		return fmt.Errorf("value is only for set")
	}

	return nil
}

func (p *Profile) validatePrior(i int, r PriorRule) error {
	if r.From == "" {
		return fmt.Errorf("trigger.prior[%d]: from is empty", i)
	}

	if r.From == AnyInspector {
		return fmt.Errorf("trigger.prior[%d]: %v need a named sender: they can weaken",
			i, r.Accept)
	}

	if len(r.Accept) == 0 {
		return fmt.Errorf("trigger.prior[%d]: accept is required", i)
	}

	for _, verb := range r.Accept {
		switch verb {
		case protocol.DoMutate, protocol.DoSkip:

		case protocol.DoChallenge, protocol.DoReauth, protocol.DoThreshold,
			protocol.DoNote:
			return fmt.Errorf("trigger.prior[%d]: %q is not ours to apply", i, verb)

		default:
			return fmt.Errorf("trigger.prior[%d]: unknown verb %q", i, verb)
		}
	}

	return nil
}
