package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-rewrite/internal/protocol"
)

func main() {
	var (
		servers = flag.String("servers", env("NATS_URL", "nats://127.0.0.1:4222"),
			"bus addresses, comma-separated")
		subject = flag.String("subject", env("WAF_REWRITE_SUBJECT", "waf.req.rewrite"),
			"inspector subject")
		name = flag.String("inspector", env("WAF_REWRITE_NAME", "rewrite"),
			"inspector name in the message")
		profile = flag.String("profile", "_probe", "route.profile value")
		uri     = flag.String("uri", "/healthcheck", "request path, optionally with a query string")
		method  = flag.String("method", "GET", "request method")
		status  = flag.Int("status", 200, "response status")
		expect  = flag.String("expect", protocol.VerdictAllow,
			"expected verdict: allow, score, redirect, deny; empty means any")
		groups = flag.Bool("groups", true,
			"require a rewrite section with an applied group in the answer")
		timeout = flag.Duration("timeout", time.Second, "how long to wait for the answer")
		quiet   = flag.Bool("quiet", false, "print nothing, only set the exit code")
	)

	flag.Parse()

	if err := run(*servers, *subject, *name, *profile, *uri, *method, *expect,
		*status, *groups, *timeout, *quiet); err != nil {

		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func run(servers, subject, name, profile, uri, method, expect string,
	status int, groups bool, timeout time.Duration, quiet bool) error {

	nc, err := nats.Connect(servers, nats.Timeout(timeout), nats.NoReconnect())
	if err != nil {
		return err
	}

	defer nc.Close()

	payload, err := json.Marshal(request(name, profile, uri, method, status, timeout))
	if err != nil {
		return err
	}

	msg, err := nc.Request(subject, payload, timeout)
	if err != nil {
		return fmt.Errorf("no verdict from %s: %w", subject, err)
	}

	var reply protocol.Reply

	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("malformed reply: %w", err)
	}

	if !quiet {
		out, _ := json.Marshal(reply)
		fmt.Println(string(out))
	}

	if expect != "" && reply.Verdict != expect {
		return fmt.Errorf("verdict is %q, expected %q", reply.Verdict, expect)
	}

	if groups && (reply.Rewrite == nil || len(reply.Rewrite.Groups) == 0) {
		return fmt.Errorf("no rewrite groups in the reply: the pipeline did " +
			"not apply the probe profile")
	}

	return nil
}

func request(name, profile, uri, method string, status int,
	timeout time.Duration) *protocol.Request {

	path, args, _ := strings.Cut(uri, "?")

	req := &protocol.Request{
		V:          protocol.Version,
		RID:        fmt.Sprintf("%016x", time.Now().UnixNano()),
		Phase:      protocol.PhaseResponse,
		Inspector:  name,
		DeadlineMS: int(timeout.Milliseconds()),
		Node:       "probe",
		Conn: protocol.Conn{
			ClientIP:   "127.0.0.1",
			ClientPort: 12345,
			ServerIP:   "127.0.0.1",
			ServerPort: 8080,
		},
		HTTP: protocol.HTTP{
			Method:   method,
			Scheme:   "http",
			Host:     "probe.local",
			URI:      path,
			ArgsSize: int64(len(args)),
			Version:  "HTTP/1.1",
		},
		Route:    protocol.Route{ServerName: "probe.local", Location: "/", Profile: profile},
		Score:    protocol.ScoreState{DenyAt: 100},
		Response: &protocol.Response{Status: status},
	}

	return req
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}
