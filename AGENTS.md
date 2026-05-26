# AGENTS.md

Project guidance for Codex and other coding agents working in this repository.

## Project

- Go module for the Caddy Layer4 plugin: `github.com/mholt/caddy-l4`.
- Keep public Caddyfile syntax aligned with existing `proxy`, `upstream`, and `dial` conventions.
- For Caddyfile parser changes, update docs and adaptation tests together.

## Verification

- Default tests: `go test ./...`
- Tidy check: `go mod tidy -diff`
- Vulnerability scan: `gopls vulncheck ./...` or `govulncheck ./...`
- Lint if installed: `golangci-lint run --timeout 10m`; fallback: `go vet ./...`

## Imported Rules

<!-- RULES IMPORT: generated from .agents/rules/*.md; edit source files there, then rerun /refine. -->

### best-practices.md

# Best Practices

Project-specific guidance for the caddy-l4 Go module.

## Project Shape

- Go module: `github.com/mholt/caddy-l4`
- Caddy Layer4 plugin with handlers, matchers, Caddyfile adapter tests, and docs.
- Module target: `go 1.25.0`; CI runs Go `1.25`; local refine ran with Go `1.26.2`.
- Primary project docs: `~/.agents/docs/projects/go.md`, `~/.agents/docs/tools/golang.md`, `~/.agents/docs/projects/caddy.md`.

## Commands

| Purpose | Command |
|---------|---------|
| Test all packages | `go test ./...` |
| Verbose CI-equivalent test | `go test -v ./...` |
| Tidy check | `go mod tidy -diff` |
| Vulnerability scan | `gopls vulncheck ./...` or `govulncheck ./...` |
| Lint if available | `golangci-lint run --timeout 10m` |
| Fallback lint | `go vet ./...` |

## Go Practices

- Use `gopls` MCP for symbol lookup, references, workspace diagnostics, and vulnerability scans before shell text searches.
- Keep Caddyfile parser changes covered by `integration/caddyfile_adapt/*.caddytest`.
- For parser-format output or examples, prefer real adapter validation over string-only assertions.
- Run `go mod tidy -diff` before dependency commits; apply `go mod tidy` only when the diff is expected.
- Do not vendor dependencies until issue #3 resolves the repository policy; this plugin has a large Caddy dependency graph.

## Caddy L4 Practices

- Preserve existing public Caddyfile vocabulary: `proxy`, `upstream`, `dial`, `local_addr`, `resolver_preference`, and `tls_*`.
- Add upstream options at the `upstream` block unless they affect the whole proxy handler.
- Preserve runtime placeholder behavior for `dial` and related connection-time fields.
- For TLS passthrough, match/sniff ClientHello data without rewriting SNI unless a feature explicitly terminates TLS.
- Document Caddyfile and JSON forms together for public directives.

## Testing

- Bug fixes follow test-first flow: add or update a failing test, then fix, then rerun.
- New Caddyfile syntax requires adaptation tests and docs updates.
- Network/proxy dialer behavior should have unit tests that assert the actual target address sent to the proxy.
- If `golangci-lint` is unavailable locally, run `go vet ./...` and report the missing lint binary.

<!-- END RULES IMPORT -->
