/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * rig-cli drives a running riglab, in the shape tdns-cli uses: a verb and an
 * RR.
 *
 *   rig-cli addrr --rr "badguy.example. CNAME ."
 *   rig-cli delrr --rr "badguy.example. CNAME ."
 *
 * The RR is the RPZ rule itself, so the policy is stated the way the zone
 * states it rather than through an invented vocabulary: the CNAME target IS
 * the action (. = NXDOMAIN, *. = NODATA, rpz-drop., rpz-passthru.).
 *
 * The owner may be written with or without the upstream feed's zone attached;
 * rig-cli asks the lab which zone that is and strips it if present. What it
 * ends up sending is always printed, because a rule that silently landed on a
 * different name than intended is the kind of thing a rig must never do.
 */
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultServer = "127.0.0.1:8099"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	verb := os.Args[1]
	args := os.Args[2:]

	switch verb {
	case "addrr":
		mutate("add", args)
	case "delrr":
		mutate("del", args)
	case "state", "zone", "info":
		simple(verb, args)
	case "log":
		logcmd(args)
	case "quit":
		simple("quit", args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "rig-cli: unknown command %q\n\n", verb)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `rig-cli -- drive a running pop rig (riglab)

  rig-cli addrr --rr "badguy.example. CNAME ."      add a rule upstream, wait for pop to serve it
  rig-cli delrr --rr "badguy.example. CNAME ."      remove it upstream, wait for pop to drop it
  rig-cli delrr --name badguy.example.              same, when the rdata is beside the point
  rig-cli state                                     what the upstream holds and what pop serves
  rig-cli zone                                      the served zone
  rig-cli log [-n 40]                               tail pop's log
  rig-cli info                                      addresses and zone names
  rig-cli quit                                      stop the lab

CNAME targets: .  = NXDOMAIN     *.            = NODATA
               rpz-drop. = DROP  rpz-passthru. = PASSTHRU (allowlist)

  --server HOST:PORT   the lab's control API (default %s, or $RIG_SERVER)
`, defaultServer)
}

func flagset(name string, args []string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	server := fs.String("server", envOr("RIG_SERVER", defaultServer), "the lab's control API")
	fs.Parse(args)
	return fs, server
}

func mutate(op string, args []string) {
	fs := flag.NewFlagSet(op+"rr", flag.ExitOnError)
	server := fs.String("server", envOr("RIG_SERVER", defaultServer), "the lab's control API")
	rrstr := fs.String("rr", "", `the RPZ rule, e.g. "badguy.example. CNAME ."`)
	name := fs.String("name", "", "the owner name alone (delrr only; --rr is preferred)")
	fs.Parse(args)

	var owner, action string
	switch {
	case *rrstr != "":
		rr, err := dns.NewRR(*rrstr)
		if err != nil {
			fatalf("cannot parse --rr %q: %v", *rrstr, err)
		}
		if rr == nil {
			fatalf("--rr %q parsed to nothing", *rrstr)
		}
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			fatalf("an RPZ rule is a CNAME; got %s", dns.TypeToString[rr.Header().Rrtype])
		}
		owner = cname.Hdr.Name
		action = actionFor(cname.Target)
		if action == "" {
			fatalf("%q is not an RPZ action target: use . (NXDOMAIN), *. (NODATA), rpz-drop. or rpz-passthru.",
				cname.Target)
		}
	case *name != "" && op == "del":
		owner = dns.Fqdn(*name)
	case *name != "":
		fatalf("addrr needs --rr: the CNAME target is the policy")
	default:
		fatalf("need --rr")
	}

	feedZone := labInfo(*server)["feed_zone"]
	sent := strings.TrimSuffix(owner, feedZone)
	if sent != owner {
		fmt.Printf("owner %s is in the feed zone %s -> sending %s\n", owner, feedZone, sent)
	}

	q := url.Values{"name": {sent}}
	if action != "" {
		q.Set("action", action)
	}
	fmt.Print(get(*server, "/"+op+"?"+q.Encode()))
}

// actionFor maps a CNAME target to the lab's action vocabulary. Returns "" for
// a target that is not an RPZ action, rather than guessing.
func actionFor(target string) string {
	switch strings.ToLower(target) {
	case ".":
		return "NXDOMAIN"
	case "*.":
		return "NODATA"
	case "rpz-drop.":
		return "DROP"
	case "rpz-passthru.":
		return "PASSTHRU"
	}
	return ""
}

func simple(path string, args []string) {
	_, server := flagset(path, args)
	fmt.Print(get(*server, "/"+path))
}

func logcmd(args []string) {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	server := fs.String("server", envOr("RIG_SERVER", defaultServer), "the lab's control API")
	n := fs.Int("n", 40, "how many lines")
	fs.Parse(args)
	fmt.Print(get(*server, fmt.Sprintf("/log?n=%d", *n)))
}

func labInfo(server string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(get(server, "/info"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			out[k] = v
		}
	}
	return out
}

func get(server, path string) string {
	if !strings.Contains(server, "://") {
		server = "http://" + server
	}
	// Generous: a mutating call blocks until the change has reached the served
	// zone, and the lab's own wait is what should time out, not this.
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(server + path)
	if err != nil {
		fatalf("%s: %v\n(is riglab running? start it with: make riglab)", server+path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fatalf("reading response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fatalf("%s: %s: %s", server+path, resp.Status, strings.TrimSpace(string(body)))
	}
	return string(body)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "rig-cli: "+format+"\n", a...)
	os.Exit(1)
}
