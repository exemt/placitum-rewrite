package decide

import (
	"github.com/exemt/placitum-rewrite/internal/config"
	"github.com/exemt/placitum-rewrite/internal/protocol"
)

type GroupRow struct {
	Group   string `json:"group"`
	Matches int    `json:"matches"`
	Headers int    `json:"headers"`
	Skipped string `json:"skipped,omitempty"`
}

type Applied struct {
	Groups []string

	Body        []byte
	BodyChanged bool

	Headers *protocol.HeaderOps

	Rows []GroupRow

	BudgetSpent bool
}

func Apply(groups []*config.Group, status int, contentType string, body []byte) Applied {
	return apply(groups, func(g *config.Group) bool {
		return g.Matches(status, contentType)
	}, body)
}

func ApplyFrame(groups []*config.Group, direction, opcode string, body []byte) Applied {
	return apply(groups, func(g *config.Group) bool {
		return g.MatchesFrame(direction, opcode)
	}, body)
}

func ForPhase(groups []*config.Group, frame bool) []*config.Group {
	var out []*config.Group

	for _, g := range groups {
		if g.OnFrame() == frame {
			out = append(out, g)
		}
	}

	return out
}

func apply(groups []*config.Group, match func(*config.Group) bool, body []byte) Applied {
	out := Applied{Body: body}
	budget := config.MatchBudget

	for _, g := range groups {
		row := GroupRow{Group: g.Name}

		if !match(g) {
			row.Skipped = "conditions"
			out.Rows = append(out.Rows, row)

			continue
		}

		if g.HasBody() && body == nil {
			row.Skipped = "no_body"
			out.Rows = append(out.Rows, row)

			continue
		}

		for _, op := range g.Body {
			if budget <= 0 {
				out.BudgetSpent = true
				row.Skipped = "budget"

				break
			}

			next, n := applyBodyOp(op, out.Body, &budget)

			if n != 0 {
				out.Body = next
				out.BodyChanged = true
				row.Matches += n
			}
		}

		for _, op := range g.Headers {
			applyHeaderOp(&out, op)
			row.Headers++
		}

		out.Groups = append(out.Groups, g.Name)
		out.Rows = append(out.Rows, row)
	}

	return out
}

func applyBodyOp(op *config.BodyOp, body []byte, budget *int) ([]byte, int) {
	limit := op.MaxMatches

	if limit > *budget {
		limit = *budget
	}

	if limit <= 0 {
		return body, 0
	}

	idx := op.Regexp().FindAllSubmatchIndex(body, limit)
	if len(idx) == 0 {
		return body, 0
	}

	*budget -= len(idx)

	out := make([]byte, 0, len(body))
	last := 0

	for _, m := range idx {
		out = append(out, body[last:m[0]]...)

		switch op.Op {
		case config.OpRemove:

		case config.OpReplace:
			out = op.Regexp().Expand(out, []byte(op.To), body, m)

		case config.OpInsertBefore:
			out = append(out, op.Text...)
			out = append(out, body[m[0]:m[1]]...)

		case config.OpInsertAfter:
			out = append(out, body[m[0]:m[1]]...)
			out = append(out, op.Text...)
		}

		last = m[1]
	}

	out = append(out, body[last:]...)

	return out, len(idx)
}

func applyHeaderOp(out *Applied, op config.HeaderOp) {
	if out.Headers == nil {
		out.Headers = &protocol.HeaderOps{}
	}

	switch op.Op {
	case config.OpSet:
		if out.Headers.Set == nil {
			out.Headers.Set = map[string]string{}
		}

		out.Headers.Set[op.Name] = op.Value

	case config.OpUnset:
		for _, have := range out.Headers.Unset {
			if have == op.Name {
				return
			}
		}

		out.Headers.Unset = append(out.Headers.Unset, op.Name)
	}
}
