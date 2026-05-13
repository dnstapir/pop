# POP Configuration Guide

POP uses a YAML configuration file. Below is a complete example with explanations for key fields.

## Example Configuration

```yaml
log:
  file: "/var/log/pop.log"    # Path to log file
  verbose: false               # Enable verbose logging
  debug: false                 # Enable debug logging

services:
  rpz:
    zonename: "rpz.example.com."                # RPZ zone name
    serialcache: "/var/cache/pop/serial.cache"  # Path to serial cache file
  reaper:
    interval: 3600   # Cleanup interval in seconds

apiserver:
  active: true
  name: "pop-api"
  key: "your-api-key"
  addresses:                   # HTTP listen addresses
    - "127.0.0.1:8080"
  tlsaddresses:                # HTTPS listen addresses
    - "0.0.0.0:8443"

dnsengine:
  active: true
  name: "pop-dns"
  addresses:
    - "127.0.0.1:53"
  logfile: "/var/log/pop-dns.log"

bootstrapserver:
  active: false                # Set to true to enable bootstrap server
  name: "pop-bootstrap"
  addresses:                   # HTTP listen addresses
    - "127.0.0.1:9090"
  tlsaddresses:                # HTTPS listen addresses
    - "0.0.0.0:9443"
  logfile: "/var/log/pop-bootstrap.log"  # Optional log file

keystore:
  path: "/etc/pop/keystore.json"   # Path to keystore file (must exist)

sources:
  example-mqtt-source:
    active: true
    name: "example-mqtt-source"
    description: "Example MQTT intelligence source"
    type: "mqtt"                   # Source type: mqtt or file
    format: "json"                 # Data format: json or rpz
    source: "mqtt://broker.example.com"
    topic: "tapir/feed/blocklist"  # MQTT topic (mqtt sources only)
    validatorkey: "path/to/validator.key"
    bootstrap:                     # Bootstrap URLs (optional)
      - "https://bootstrap.example.com/feed"
    bootstrapurl: "https://bootstrap.example.com"
    bootstrapkey: "path/to/bootstrap.key"

  example-file-source:
    active: true
    name: "example-file-source"
    description: "Example local file source"
    type: "file"
    format: "rpz"
    source: "local"
    filename: "/etc/pop/blocklist.rpz"  # Local file path (file sources only)
    immutable: false                     # If true, source will not be updated

policy:
  logfile: "/var/log/pop-policy.log"   # Optional policy log file
  allowlist:
    action: "accept"          # Action for allowlisted domains
  denylist:
    action: "drop"            # Action for denylisted domains
  doubtlist:
    numsources:
      limit: 3                # Block if domain seen in this many sources
      action: "drop"
    numtapirtags:
      limit: 2                # Block if domain has this many TAPIR tags
      action: "drop"
    denytapir:
      tags:                   # Block if domain has any of these TAPIR tags
        - "malware"
        - "phishing"
      action: "drop"
```

## Required Fields

All fields are required unless marked as optional.

| Section | Field | Required | Description |
|---------|-------|----------|-------------|
| log | file | ✅ | Log file path |
| log | verbose | ✅ | Enable verbose logging |
| log | debug | ✅ | Enable debug logging |
| services.rpz | zonename | ✅ | RPZ zone name |
| services.rpz | serialcache | ✅ | Serial cache file path |
| services.reaper | interval | ✅ | Cleanup interval in seconds |
| apiserver | active | ✅ | Enable API server |
| apiserver | name | ✅ | API server name |
| apiserver | key | ✅ | API authentication key |
| apiserver | addresses | ✅ | HTTP listen addresses |
| apiserver | tlsaddresses | ✅ | HTTPS listen addresses |
| dnsengine | active | ✅ | Enable DNS engine |
| dnsengine | name | ✅ | DNS engine name |
| dnsengine | addresses | ✅ | DNS listen addresses |
| dnsengine | logfile | ✅ | DNS engine log file |
| bootstrapserver | active | ✅ | Enable bootstrap server |
| bootstrapserver | name | ✅ | Bootstrap server name |
| bootstrapserver | addresses | ✅ | HTTP listen addresses |
| bootstrapserver | tlsaddresses | ✅ | HTTPS listen addresses |
| bootstrapserver | logfile | ➖ | Log file path (optional) |
| keystore | path | ✅ | Path to keystore file (must exist) |
| sources.* | active | ✅ | Enable this source |
| sources.* | name | ✅ | Source name |
| sources.* | description | ✅ | Source description |
| sources.* | type | ✅ | Source type: `mqtt` or `file` |
| sources.* | format | ✅ | Data format: `json` or `rpz` |
| sources.* | source | ✅ | Source connection string |
| sources.* | topic | ➖ | MQTT topic (mqtt sources only) |
| sources.* | filename | ➖ | Local file path (file sources only) |
| sources.* | immutable | ➖ | Prevent source updates (optional, default: false) |
| sources.* | validatorkey | ➖ | Path to validator key (optional) |
| sources.* | bootstrap | ➖ | Bootstrap URLs (optional) |
| sources.* | bootstrapurl | ➖ | Bootstrap server URL (optional) |
| sources.* | bootstrapkey | ➖ | Bootstrap key path (optional) |
| policy | logfile | ➖ | Policy log file (optional) |
| policy.allowlist | action | ✅ | Action for allowlisted domains |
| policy.denylist | action | ✅ | Action for denylisted domains |
| policy.doubtlist.numsources | limit | ✅ | Source count threshold |
| policy.doubtlist.numsources | action | ✅ | Action when threshold exceeded |
| policy.doubtlist.numtapirtags | limit | ✅ | TAPIR tag count threshold |
| policy.doubtlist.numtapirtags | action | ✅ | Action when threshold exceeded |
| policy.doubtlist.denytapir | tags | ✅ | TAPIR tags that trigger denial |
| policy.doubtlist.denytapir | action | ✅ | Action for matched tags |