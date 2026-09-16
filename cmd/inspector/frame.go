package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/exemt/placitum-rewrite/internal/audit"
	"github.com/exemt/placitum-rewrite/internal/config"
	"github.com/exemt/placitum-rewrite/internal/decide"
	"github.com/exemt/placitum-rewrite/internal/protocol"
)

func (h *handler) inspectFrame(
	req *protocol.Request,
	p *config.Profile,
	ask decide.Ask,
	det audit.Details,
	started time.Time,
	budget time.Duration,
) (*protocol.Reply, audit.Details) {
	direction, opcode := "", ""

	if req.Stream != nil {
		direction, opcode = req.Stream.Direction, req.Stream.Opcode
	}

	det.Engine["conn"] = req.ConnID
	det.Engine["seq"] = req.Seq
	det.Engine["direction"] = direction
	det.Engine["opcode"] = opcode

	active := decide.ForPhase(ask.Active(p), true)
	if len(active) == 0 {
		det.EngineMS = engineMS(started)

		return h.plain(req, protocol.VerdictAllow, decide.CodeNoop), det
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	var (
		raw         []byte
		bodyMissing bool
	)

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

	applied := decide.ApplyFrame(active, direction, opcode, raw)

	det.Engine["groups"] = applied.Rows

	if applied.BudgetSpent {
		det.Engine["budget_spent"] = true
	}

	if bodyMissing && frameBodyWanted(active, direction, opcode) {
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

	if len(applied.Groups) == 0 || !applied.BodyChanged {
		reply.Reason = &protocol.Reason{Code: decide.CodeNoop}
		det.EngineMS = engineMS(started)

		return reply, det
	}

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

	reply.Rewrite = &protocol.Rewrite{
		Groups: applied.Groups,
		Body: &protocol.RewriteBody{
			Key:    key,
			Size:   int64(len(applied.Body)),
			SHA256: hex.EncodeToString(sum[:]),
		},
	}

	det.Engine["bytes_in"] = len(raw)
	det.Engine["bytes_out"] = len(applied.Body)
	det.Engine["applied"] = applied.Groups
	det.EngineMS = engineMS(started)

	h.log.Info("frame rewritten",
		"rid", req.RID,
		"conn", req.ConnID,
		"seq", req.Seq,
		"direction", direction,
		"opcode", opcode,
		"uri", req.HTTP.URI,
		"profile", p.Name,
		"groups", applied.Groups,
		"bytes_in", len(raw),
		"bytes_out", len(applied.Body),
		"engine_ms", det.EngineMS,
	)

	return reply, det
}

func frameBodyWanted(groups []*config.Group, direction, opcode string) bool {
	for _, g := range groups {
		if g.HasBody() && g.MatchesFrame(direction, opcode) {
			return true
		}
	}

	return false
}
