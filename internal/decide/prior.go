package decide

import (
	"github.com/exemt/placitum-rewrite/internal/config"
	"github.com/exemt/placitum-rewrite/internal/protocol"
)

const (
	CodeSkipped            = "REWRITE_SKIPPED"
	CodeNoop               = "REWRITE_NOOP"
	CodeApplied            = "REWRITE_APPLIED"
	CodeObserve            = "REWRITE_OBSERVE"
	CodeProfileOff         = "REWRITE_PROFILE_OFF"
	CodeUnknownProfile     = "REWRITE_UNKNOWN_PROFILE"
	CodePhaseNotSupported  = "REWRITE_PHASE_NOT_SUPPORTED"
	CodeBodyUnavailable    = "REWRITE_BODY_UNAVAILABLE"
	CodeStoreUnavailable   = "REWRITE_STORE_UNAVAILABLE"
	CodeStoreError         = "REWRITE_STORE_ERROR"
	CodeInternalError      = "REWRITE_INTERNAL_ERROR"
	CodeMalformedRequest   = "REWRITE_MALFORMED_REQUEST"
	CodeUnsupportedVersion = "REWRITE_UNSUPPORTED_VERSION"
)

const (
	OutcomeApplied      = "applied"
	OutcomeNoRule       = "no_rule"
	OutcomeUnknownGroup = "unknown_group"
)

type Ask struct {
	Skip bool

	On  map[string]bool
	Off map[string]bool

	Outcomes []ActionOutcome
}

type ActionOutcome struct {
	From    string   `json:"from"`
	Do      string   `json:"do"`
	Apply   string   `json:"apply"`
	Code    string   `json:"code,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Outcome string   `json:"outcome"`
}

func (a Ask) Active(p *config.Profile) []*config.Group {
	var out []*config.Group

	for _, g := range p.Groups {
		on := g.Default

		if a.On[g.Name] {
			on = true
		}

		if a.Off[g.Name] {
			on = false
		}

		if on {
			out = append(out, g)
		}
	}

	return out
}

func EvaluatePrior(entries []protocol.PriorVerdict, p *config.Profile) Ask {
	a := Ask{On: map[string]bool{}, Off: map[string]bool{}}

	if p == nil {
		return a
	}

	known := map[string]bool{}

	for _, g := range p.Groups {
		known[g.Name] = true
	}

	for _, v := range entries {
		for _, act := range v.Actions {
			a.deliver(v.Inspector, act, p.Trigger.Prior, known)
		}
	}

	return a
}

func (a *Ask) deliver(from string, act protocol.Action, rules []config.PriorRule, known map[string]bool) {
	out := ActionOutcome{
		From:    from,
		Do:      act.Do,
		Apply:   act.Scope(),
		Code:    act.Code,
		Outcome: OutcomeNoRule,
	}

	for _, r := range rules {
		if r.From != from {
			continue
		}

		if !r.Accepts(act.Do) || !r.WantsCode(act.Code) {
			continue
		}

		if act.Scope() != protocol.ApplyRequest {
			continue
		}

		switch act.Do {
		case protocol.DoSkip:
			a.Skip = true
			out.Outcome = OutcomeApplied

		case protocol.DoMutate:
			if !known[act.Group] {
				out.Groups = append(out.Groups, "?"+act.Group)
				out.Outcome = OutcomeUnknownGroup
				break
			}

			if act.Set == config.SetOff {
				a.Off[act.Group] = true
				out.Groups = append(out.Groups, "-"+act.Group)
			} else {
				a.On[act.Group] = true
				out.Groups = append(out.Groups, "+"+act.Group)
			}

			out.Outcome = OutcomeApplied
		}
	}

	a.Outcomes = append(a.Outcomes, out)
}
