# POP Configuration Guide

POP loads configuration from four separate YAML files at startup, all located in `/etc/dnstapir/`:

| File | Purpose |
|------|---------|
| `dnstapir-pop.yaml` | Main config: logging, services, API/DNS/bootstrap servers, keystore |
| `pop-sources.yaml` | Intelligence sources (MQTT, file, RPZ zone transfer) |
| `pop-outputs.yaml` | RPZ downstream outputs |
| `pop-policy.yaml` | Policy rules for allow/deny/doubtlist decisions |

---

## dnstapir-pop.yaml

```yaml
log:
  file: "/var/log/dnstapir/pop.log"
  verbose: false
  debug: false

services:
  rpz:
    zonename: "rpz.example.com."
    serialcache: "/var/cache/dnstapir/pop-serial.yaml"
  reaper:
    interval: 3600

apiserver:
  active: true
  name: "pop-api"
  key: "your-api-key"
  addresses:
    - "127.0.0.1:8080"
  tlsaddresses:
    - "0.0.0.0:8443"

dnsengine:
  active: true
  name: "pop-dns"
  addresses:
    - "127.0.0.1:53"
  logfile: "/var/log/dnstapir/pop-dns.log"

bootstrapserver:
  active: false
  name: "pop-bootstrap"
  addresses:
    - "127.0.0.1:9090"
  tlsaddresses:
    - "0.0.0.0:9443"
  logfile: "/var/log/dnstapir/pop-bootstrap.log"

keystore:
  path: "/etc/dnstapir/keystore.json"
```

### Field reference

| Field | Required | Description |
|-------|----------|-------------|
| `log.file` | yes | Log file path |
| `log.verbose` | yes | Enable verbose logging |
| `log.debug` | yes | Enable debug logging |
| `services.rpz.zonename` | yes | RPZ zone name served to downstream resolvers |
| `services.rpz.serialcache` | yes | File where the current RPZ serial is persisted across restarts |
| `services.reaper.interval` | yes | Interval in seconds for the cleanup (reaper) goroutine |
| `apiserver.active` | yes | Enable the REST API server |
| `apiserver.name` | yes | API server identifier |
| `apiserver.key` | yes | API authentication key |
| `apiserver.addresses` | yes | HTTP listen addresses (list) |
| `apiserver.tlsaddresses` | yes | HTTPS listen addresses (list) |
| `dnsengine.active` | yes | Enable the DNS engine |
| `dnsengine.name` | yes | DNS engine identifier |
| `dnsengine.addresses` | yes | DNS listen addresses (list) |
| `dnsengine.logfile` | yes | DNS engine log file path |
| `bootstrapserver.active` | yes | Enable the bootstrap server |
| `bootstrapserver.name` | yes | Bootstrap server identifier |
| `bootstrapserver.addresses` | yes | HTTP listen addresses (list) |
| `bootstrapserver.tlsaddresses` | yes | HTTPS listen addresses (list) |
| `bootstrapserver.logfile` | no | Bootstrap server log file path |
| `keystore.path` | yes | Path to the keystore file (must already exist) |

---

## pop-sources.yaml

Each entry under `sources` defines one intelligence feed. The `source` field controls how the data is fetched; the `type` field controls which list the data is loaded into.

```yaml
sources:
  # MQTT-based intelligence feed
  tapir-mqtt-feed:
    active: true
    name: "tapir-mqtt-feed"
    description: "DNS TAPIR MQTT intelligence feed"
    type: "doubtlist"        # List to load into: allowlist, denylist, or doubtlist
    format: "json"           # Wire format: json
    source: "mqtt"           # Fetch method: mqtt, file, or xfr
    topic: "tapir/feed/blocklist"
    validatorkey: "/etc/dnstapir/validator.key"
    bootstrap:
      - "https://bootstrap.example.com/feed"
    bootstrapurl: "https://bootstrap.example.com"
    bootstrapkey: "/etc/dnstapir/bootstrap.key"

  # Local domain list (plain text, one domain per line)
  local-allowlist:
    active: true
    name: "local-allowlist"
    description: "Locally managed allowlist"
    type: "allowlist"
    format: "domains"        # File format: domains, csv, or dawg
    source: "file"
    filename: "/etc/dnstapir/allowlist.txt"
    immutable: false         # If true, the list is never updated at runtime

  # RPZ zone transfer feed
  upstream-rpz:
    active: true
    name: "upstream-rpz"
    description: "Upstream RPZ denylist via zone transfer"
    type: "denylist"
    format: "rpz"
    source: "xfr"
    upstream: "192.0.2.1:53"
    zone: "blocklist.example.com."
```

### Field reference

| Field | Required | Description |
|-------|----------|-------------|
| `active` | yes | Enable this source |
| `name` | yes | Source identifier |
| `description` | yes | Human-readable description |
| `type` | yes | Target list: `allowlist`, `denylist`, or `doubtlist` |
| `format` | yes | Data format. For `source: mqtt`: `json`. For `source: file`: `domains`, `csv`, or `dawg`. For `source: xfr`: `rpz` |
| `source` | yes | Fetch method: `mqtt`, `file`, or `xfr` |
| `topic` | required when `source: mqtt` | MQTT topic to subscribe to |
| `validatorkey` | no | Path to the key used to verify signed MQTT messages |
| `bootstrap` | no | List of bootstrap server URLs for initial data load (`source: mqtt` only) |
| `bootstrapurl` | no | Bootstrap server base URL (`source: mqtt` only) |
| `bootstrapkey` | no | Path to the bootstrap authentication key (`source: mqtt` only) |
| `filename` | required when `source: file` | Path to the local file |
| `immutable` | no | If `true`, the list is never refreshed at runtime (default: `false`) |
| `upstream` | required when `source: xfr` | Upstream DNS server address `host:port` for zone transfer |
| `zone` | required when `source: xfr` | Zone name to transfer |

**Note on `type: allowlist` with DAWG format:** DAWG files are only supported for `type: allowlist`.

---

## pop-outputs.yaml

Outputs define downstream DNS resolvers that receive RPZ NOTIFY and can perform AXFR/IXFR.

```yaml
outputs:
  downstream-resolver:
    active: true
    name: "downstream-resolver"
    description: "Primary downstream DNS resolver"
    type: "doubtlist"
    format: "rpz"
    downstream: "192.0.2.10:53"
```

### Field reference

| Field | Required | Description |
|-------|----------|-------------|
| `active` | yes | Enable this output |
| `name` | yes | Output identifier |
| `description` | yes | Human-readable description |
| `type` | yes | Source list type this output is derived from |
| `format` | yes | Output format (`rpz`) |
| `downstream` | yes | Downstream resolver address `host:port` to send DNS NOTIFY to |

---

## pop-policy.yaml

Policy rules determine what RPZ action is applied to names found in each list.

```yaml
policy:
  logfile: "/var/log/dnstapir/pop-policy.log"
  allowlist:
    action: "allowlist"
  denylist:
    action: "nxdomain"
  doubtlist:
    numsources:
      limit: 3
      action: "nxdomain"
    numtapirtags:
      limit: 2
      action: "drop"
    denytapir:
      tags:
        - "malware"
        - "phishing"
      action: "drop"
```

### Field reference

| Field | Required | Description |
|-------|----------|-------------|
| `policy.logfile` | no | Policy decision log file path |
| `policy.allowlist.action` | yes | Action for allowlisted names |
| `policy.denylist.action` | yes | Action for denylisted names |
| `policy.doubtlist.numsources.limit` | yes | Block if a name appears in this many or more doubtlist sources |
| `policy.doubtlist.numsources.action` | yes | Action when `numsources.limit` is reached |
| `policy.doubtlist.numtapirtags.limit` | yes | Block if a name carries this many or more TAPIR tags |
| `policy.doubtlist.numtapirtags.action` | yes | Action when `numtapirtags.limit` is reached |
| `policy.doubtlist.denytapir.tags` | yes | Block if a name carries any of these TAPIR tags |
| `policy.doubtlist.denytapir.action` | yes | Action when a tag in `denytapir.tags` is matched |

### Valid action values

| Value | RPZ effect |
|-------|-----------|
| `allowlist` or `passthru` | `rpz-passthru.` — allow the name through |
| `nxdomain` | `.` — return NXDOMAIN |
| `nodata` | `*.` — return NODATA |
| `drop` | `rpz-drop.` — silently drop the query |
| `redirect` | redirect (target TBD in upstream config) |

### Policy examples

**Strict — block anything doubtful:**
```yaml
policy:
  allowlist:
    action: "allowlist"
  denylist:
    action: "nxdomain"
  doubtlist:
    numsources:
      limit: 1        # Block if seen in even one source
      action: "nxdomain"
    numtapirtags:
      limit: 1        # Block if any TAPIR tag present
      action: "nxdomain"
    denytapir:
      tags:
        - "malware"
        - "phishing"
        - "botnet"
      action: "nxdomain"
```

**Permissive — only block high-confidence threats:**
```yaml
policy:
  allowlist:
    action: "allowlist"
  denylist:
    action: "drop"
  doubtlist:
    numsources:
      limit: 5        # Require corroboration from multiple sources
      action: "drop"
    numtapirtags:
      limit: 3        # Require several TAPIR tags before blocking
      action: "drop"
    denytapir:
      tags:
        - "malware"
      action: "nxdomain"
```

**Silent drop — hide blocking from clients:**
```yaml
policy:
  allowlist:
    action: "allowlist"
  denylist:
    action: "drop"
  doubtlist:
    numsources:
      limit: 2
      action: "drop"
    numtapirtags:
      limit: 2
      action: "drop"
    denytapir:
      tags:
        - "malware"
        - "phishing"
      action: "drop"
```

---

## List file formats

File-based sources (`source: file`) support three formats, set via the `format` field.

### domains

Plain text, one fully-qualified domain name per line. Lines are read as-is and converted to FQDN (trailing dot appended if missing).

```
example.com
malicious.example.org
blocked.test.
```

### csv

CSV file with a header row (skipped) and the domain name in the **second column** (index 1).

```
id,domain,category
1,malicious.example.com,malware
2,phishing.example.org,phishing
```

### dawg

A pre-built binary [DAWG](https://github.com/smhanov/dawg) (Directed Acyclic Word Graph) file. DAWG is a compact, read-only data structure optimised for large allowlists.

- Only supported for `type: allowlist`
- Build a DAWG file from a sorted domain list using the `tapir` CLI tool
- The file is loaded directly at startup; runtime updates are not supported
