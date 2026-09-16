package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-rewrite/internal/audit"
	"github.com/exemt/placitum-rewrite/internal/body"
	"github.com/exemt/placitum-rewrite/internal/config"
	"github.com/exemt/placitum-rewrite/internal/decide"
	"github.com/exemt/placitum-rewrite/internal/protocol"
	"github.com/exemt/placitum-rewrite/internal/queue"
)

type bodyWriter interface {
	Put(ctx context.Context, key string, value []byte, ttl time.Duration) error
}

type handler struct {
	cfg    *config.Config
	log    *slog.Logger
	nc     *nats.Conn
	audit  *audit.Sink
	store  *config.Store
	loader *body.Loader
	writer bodyWriter
	pool   *queue.Pool
}

func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		rid := ""

		var pe *protocol.ParseError
		if errors.As(err, &pe) {
			rid = pe.RID
		}

		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, protocol.FallbackReply(rid, h.cfg.Name, decide.CodeMalformedRequest),
			nil, audit.Details{})

		return
	}

	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, decide.CodeUnsupportedVersion)
		reply.V = protocol.Version

		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	if req.Release != nil {
		h.log.Debug("release ignored", "rid", req.RID, "reason", req.Release.Reason)

		return
	}

	if req.Phase != protocol.PhaseResponse && req.Phase != protocol.PhaseFrame {
		h.send(msg.Reply, protocol.ErrorReply(req, decide.CodePhaseNotSupported),
			req, audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds())

		h.send(t.Reply, protocol.ShedReply(t.Req, shed), t.Req, audit.Details{
			Engine: map[string]any{
				"shed":      shed,
				"budget_ms": float64(budget.Microseconds()) / 1000,
			},
		})

		return
	}

	reply, det := h.inspect(t, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(t *queue.Task, budget time.Duration) (*protocol.Reply, audit.Details) {
	req := t.Req
	snap := h.store.Current()

	p, ok := h.profile(snap, req)
	if !ok {
		h.log.Warn("unknown profile", "rid", req.RID,
			"profile", req.Route.Profile)

		return protocol.ErrorReply(req, decide.CodeUnknownProfile), audit.Details{}
	}

	if p.Mode == config.ModeOff {
		return h.plain(req, protocol.VerdictAllow, decide.CodeProfileOff), audit.Details{}
	}

	started := time.Now()

	ask := decide.EvaluatePrior(req.Prior, p)

	det := audit.Details{Engine: map[string]any{
		"profile": p.Name,
		"mode":    p.Mode,
	}}

	if p.Mode == config.ModeObserve {
		det.Engine["passive"] = true
	}

	if len(ask.Outcomes) != 0 {
		det.Engine["actions"] = ask.Outcomes
	}

	if ask.Skip {
		det.EngineMS = engineMS(started)

		return h.plain(req, protocol.VerdictAllow, decide.CodeSkipped), det
	}

	if req.Phase == protocol.PhaseFrame {
		return h.inspectFrame(req, p, ask, det, started, budget)
	}

	active := decide.ForPhase(ask.Active(p), false)
	if len(active) == 0 {
		det.EngineMS = engineMS(started)

		return h.plain(req, protocol.VerdictAllow, decide.CodeNoop), det
	}

	status := 0
	if req.Response != nil {
		status = req.Response.Status
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	contentType := h.contentType(ctx, req, active)

	var (
		raw         []byte
		bodyMissing bool
	)

	if groupsNeedBody(active) {
		loaded := h.loader.Load(ctx, req.Store.Body)

		if loaded.Failed() {
			h.log.Error("store fetch failed", "rid", req.RID, "profile", p.Name,
				"reason", loaded.Unavailable)

			det.EngineMS = engineMS(started)
			det.Engine["store"] = loaded.Unavailable

			return protocol.ErrorReply(req, decide.CodeStoreUnavailable), det
		}

		switch {
		case loaded.Available() && !loaded.Truncated:
			raw = loaded.Data

		default:
			bodyMissing = true
		}
	}

	applied := decide.Apply(active, status, contentType, raw)

	det.Engine["groups"] = applied.Rows

	if applied.BudgetSpent {
		det.Engine["budget_spent"] = true
	}

	if bodyMissing && bodyWanted(active, status, contentType) {
		det.EngineMS = engineMS(started)

		return h.failPer(p, req, decide.CodeBodyUnavailable, applied, det)
	}

	if p.Mode == config.ModeObserve {
		det.EngineMS = engineMS(started)

		if len(applied.Groups) == 0 {
			return h.plain(req, protocol.VerdictAllow, decide.CodeNoop), det
		}

		det.Engine["would_apply"] = applied.Groups

		return h.plain(req, protocol.VerdictAllow, decide.CodeObserve), det
	}

	reply := h.plain(req, protocol.VerdictAllow, decide.CodeApplied)

	if len(applied.Groups) == 0 {
		reply.Reason = &protocol.Reason{Code: decide.CodeNoop}
		det.EngineMS = engineMS(started)

		return reply, det
	}

	if applied.Headers != nil {
		reply.Headers = applied.Headers
	}

	reply.Rewrite = &protocol.Rewrite{Groups: applied.Groups}

	if applied.BodyChanged {
		key := req.Store.Body.Key + config.OutSuffix

		if h.writer == nil {
			det.EngineMS = engineMS(started)

			return h.failPer(p, req, decide.CodeStoreError, applied, det)
		}

		if err := h.writer.Put(ctx, key, applied.Body, config.OutTTL); err != nil {
			h.log.Warn("out object put failed", "rid", req.RID, "key", key,
				"error", err.Error())

			det.EngineMS = engineMS(started)

			return h.failPer(p, req, decide.CodeStoreError, applied, det)
		}

		sum := sha256.Sum256(applied.Body)

		reply.Rewrite.Body = &protocol.RewriteBody{
			Key:    key,
			Size:   int64(len(applied.Body)),
			SHA256: hex.EncodeToString(sum[:]),
		}

		det.Engine["bytes_in"] = len(raw)
		det.Engine["bytes_out"] = len(applied.Body)
	}

	det.Engine["applied"] = applied.Groups
	det.EngineMS = engineMS(started)

	h.log.Info("rewritten",
		"rid", req.RID,
		"uri", req.HTTP.URI,
		"profile", p.Name,
		"groups", applied.Groups,
		"body_changed", applied.BodyChanged,
		"engine_ms", det.EngineMS,
	)

	return reply, det
}

func (h *handler) failPer(
	p *config.Profile,
	req *protocol.Request,
	code string,
	applied decide.Applied,
	det audit.Details,
) (*protocol.Reply, audit.Details) {
	det.Engine["error"] = code

	if p.Mode == config.ModeObserve {
		return h.plain(req, protocol.VerdictAllow, code), det
	}

	reply := h.plain(req, protocol.VerdictDeny, code)
	reply.Response = &protocol.ResponseRef{Name: p.DenyResponse}

	return reply, det
}

func (h *handler) contentType(
	ctx context.Context,
	req *protocol.Request,
	active []*config.Group,
) string {
	need := false

	for _, g := range active {
		if len(g.ContentType) != 0 {
			need = true
			break
		}
	}

	if !need {
		return ""
	}

	if req.Response != nil {
		for _, p := range req.Response.Headers {
			if strings.EqualFold(p.Name(), "content-type") {
				return p.Value()
			}
		}
	}

	loaded := h.loader.Load(ctx, req.Store.Headers)
	if !loaded.Available() || len(loaded.Data) == 0 {
		return ""
	}

	var pairs []protocol.Header

	if err := json.Unmarshal(loaded.Data, &pairs); err != nil {
		h.log.Warn("headers blob is not an array of pairs", "rid", req.RID,
			"error", err.Error())

		return ""
	}

	for _, p := range pairs {
		if strings.EqualFold(p.Name(), "content-type") {
			return p.Value()
		}
	}

	return ""
}

func groupsNeedBody(groups []*config.Group) bool {
	for _, g := range groups {
		if g.HasBody() {
			return true
		}
	}

	return false
}

func bodyWanted(groups []*config.Group, status int, contentType string) bool {
	for _, g := range groups {
		if g.HasBody() && g.Matches(status, contentType) {
			return true
		}
	}

	return false
}

func (h *handler) profile(snap *config.Snapshot, req *protocol.Request) (*config.Profile, bool) {
	return snap.Profile(req.Route.Profile)
}

func engineMS(started time.Time) float64 {
	return float64(time.Since(started).Microseconds()) / 1000
}

func (h *handler) plain(req *protocol.Request, verdict, code string) *protocol.Reply {
	reply := protocol.NewReply(req, verdict)
	reply.Reason = &protocol.Reason{Code: code}

	return reply
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)

		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		fallback := protocol.FallbackReply(reply.RID, reply.Inspector, decide.CodeInternalError)

		payload, err = fallback.Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject == "" {
		return
	}

	h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, decide.CodeInternalError),
		nil, audit.Details{})
}
