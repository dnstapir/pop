# Refactor `dnstapir-pop` Into `cmd/pop` + Root `pop` Package

## Summary

Move the executable entrypoint to `cmd/pop` and convert the repo root into package `pop`. The root package exposes a library-style `Run` API, while `cmd/pop/main.go` owns process concerns such as signals, stderr reporting, and exit codes.

## Public API And Layout

- Keep functionality in the repo root as `package pop`; do not create a `/pop` subdirectory.
- Add:
  ```go
  type RunOptions struct {
      Name, Version, Commit string
      Args []string
      Stdout, Stderr io.Writer
      Reload <-chan struct{}
  }

  func Run(ctx context.Context, opts RunOptions) error
  ```
- `cmd/pop/main.go` defines the ldflag-backed `name`, `version`, and `commit` vars, installs SIGINT/SIGTERM context cancellation, converts SIGHUP into `RunOptions.Reload`, calls `pop.Run`, and uses `os.Exit(1)` only on returned errors.
- Remove root globals used only by the old executable path: `Gconfig`, `mqttclientid`, and `POPExiter`.

## Implementation Changes

- Rename all root Go files from `package main` to `package pop`; move the old startup logic out of `main()` into `Run`.
- Update `Makefile` so `make build` runs `go build ... -o out/dnstapir-pop ./cmd/pop`; keep package/install artifacts and binary name unchanged.
- Replace process exits in `pop` with returned errors:
  - `SetupLogging`, config validation/loading, MQTT setup/start, source parsing, output parsing, bootstrap setup, and policy parsing return contextual errors.
  - `log.Fatal`, `os.Exit`, `panic`, `log.Panicf`, and `POPExiter` disappear from package `pop` for normal failure paths.
- Convert long-running workers to context/error style:
  - `DnsEngine(ctx, *Config) error`
  - `APIhandler(ctx, *Config) error`
  - `ConfigUpdater(ctx, *Config) error`
  - `StatusUpdater(ctx, *Config) error`
  - `RefreshEngine(ctx, *Config) error`
- `Run` starts workers, watches worker errors, context cancellation, API stop requests, and reload events; it saves the RPZ serial before returning.
- Remove `MqttEngine.SetupInterruptHandler()` from the library path; shutdown should flow through `Run` and `StopEngine`.
- Update policy/RPZ helper signatures where needed so invalid list/zone formats return errors instead of exiting, and propagate those errors through RPZ generation.
- Fix the current vet-blocking format string issues encountered in `configupdater.go`, `refreshengine.go`, and `statusupdater.go` as part of making `go test ./...` meaningful after the refactor.

## Test Plan

- Run `gofmt` on touched Go files.
- Run `go list ./...` and confirm packages include `dnstapir-pop` and `dnstapir-pop/cmd/pop`.
- Run `go test ./...`; expected target is green after the pre-existing vet issues are fixed.
- Run `make build` and confirm `out/dnstapir-pop` is produced with ldflag metadata wired through `cmd/pop`.
- Verify with search that `POPExiter`, root-package `os.Exit`, `log.Fatal`, and normal-error `panic` usages are gone.

## Assumptions

- The official library entrypoint is `pop.Run`; existing exported helper names can remain, but signatures may gain `context.Context` or `error` to satisfy the strict library API.
- Config file paths, service names, package install paths, and runtime behavior stay the same unless needed to remove process exits.
- Only `cmd/pop` may terminate the process; package `pop` reports failures to its caller.
