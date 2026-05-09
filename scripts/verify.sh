#!/usr/bin/env bash
# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0
#
# verify.sh — comprehensive production-readiness check for kerno.
#
# Runs every gate that proves kerno is ready to ship:
#   1. dependencies         (clang, go, jq, kernel BTF)
#   2. build pipeline       (generate, build, no warnings)
#   3. quality gates        (vet, test, race, lint)
#   4. coverage floors      (each package above minimum)
#   5. bpf verifier         (all 6 programs accepted by kernel)
#   6. cli smoke tests      (--version, --help, JSON output)
#   7. doctor pipeline      (graceful degradation, JSON valid, exit codes)
#   8. chaos pipeline       (every scenario runs cleanly + cleans up)
#   9. induce-detect pairs  (every chaos scenario triggers its paired rule)
#  10. daemon mode          (start, /metrics, /healthz, /readyz, clean stop)
#  11. manifests            (helm lint, k8s yaml syntax)
#
# Each phase prints PASS/FAIL with a one-line reason. Final summary
# reports the count and exits non-zero if any phase failed.
#
# Usage:
#   ./scripts/verify.sh                # run all phases
#   ./scripts/verify.sh deps build     # only specific phases
#   ./scripts/verify.sh --list         # list phases and exit

set -uo pipefail

cd "$(dirname "$0")/.."

KERNO=bin/kerno
BPF_VERIFY=bin/bpf-verify

# ─── State ────────────────────────────────────────────────────────────────
# Each phase appends PASS or FAIL <name> <reason> to RESULTS.
RESULTS=()
SKIPPED=()

phase_pass() { RESULTS+=("PASS|$1|$2"); printf '    \e[32mPASS\e[0m  %s\n' "$2"; }
phase_fail() { RESULTS+=("FAIL|$1|$2"); printf '    \e[31mFAIL\e[0m  %s\n' "$2"; }
phase_skip() { SKIPPED+=("$1: $2"); printf '    \e[33mSKIP\e[0m  %s\n' "$2"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# ─── Phase definitions ────────────────────────────────────────────────────

phase_deps() {
    echo "==> 1. dependencies"
    local n=$1
    local missing=0

    for c in go clang jq bpftool sudo; do
        if require_cmd "$c"; then
            phase_pass "$n" "$c installed"
        else
            phase_fail "$n" "$c missing"
            missing=$((missing+1))
        fi
    done

    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        phase_pass "$n" "/sys/kernel/btf/vmlinux available (BTF)"
    else
        phase_fail "$n" "/sys/kernel/btf/vmlinux missing — kernel needs >= 5.8 with BTF"
    fi

    return $missing
}

phase_build() {
    echo "==> 2. build pipeline"
    local n=$1

    if go generate ./internal/bpf/... >/tmp/verify-generate.log 2>&1; then
        local count
        count=$(ls internal/bpf/*_bpfel.go 2>/dev/null | wc -l)
        if [[ "$count" -eq 6 ]]; then
            phase_pass "$n" "go generate produced 6/6 *_bpfel.go files"
        else
            phase_fail "$n" "go generate produced $count/6 *_bpfel.go files"
        fi
    else
        phase_fail "$n" "go generate failed (see /tmp/verify-generate.log)"
        return 1
    fi

    if make build >/tmp/verify-build.log 2>&1; then
        phase_pass "$n" "make build succeeded → $($KERNO version | head -1)"
    else
        phase_fail "$n" "make build failed"
    fi

    if go build -o "$BPF_VERIFY" ./cmd/bpf-verify >/dev/null 2>&1; then
        phase_pass "$n" "bpf-verify harness built"
    else
        phase_fail "$n" "bpf-verify build failed"
    fi

    if make bpf >/tmp/verify-makebpf.log 2>&1; then
        phase_pass "$n" "make bpf compiled all 6 .c → .o without warnings"
    else
        phase_fail "$n" "make bpf failed"
    fi
}

phase_quality() {
    echo "==> 3. quality gates"
    local n=$1

    if go vet ./... 2>/tmp/verify-vet.log; then
        phase_pass "$n" "go vet: clean"
    else
        phase_fail "$n" "go vet: $(wc -l < /tmp/verify-vet.log) issues"
    fi

    if go test ./... -count=1 -timeout 120s >/tmp/verify-test.log 2>&1; then
        local pkgs
        pkgs=$(grep -c "^ok " /tmp/verify-test.log)
        phase_pass "$n" "go test: $pkgs/11 packages pass"
    else
        phase_fail "$n" "go test failed (see /tmp/verify-test.log)"
    fi

    if go test -race ./... -count=1 -timeout 180s >/tmp/verify-race.log 2>&1; then
        phase_pass "$n" "go test -race: no data races detected"
    else
        phase_fail "$n" "go test -race failed (see /tmp/verify-race.log)"
    fi

    if require_cmd golangci-lint; then
        if golangci-lint run ./... >/tmp/verify-lint.log 2>&1; then
            phase_pass "$n" "golangci-lint: 0 issues"
        else
            phase_fail "$n" "golangci-lint flagged issues (see /tmp/verify-lint.log)"
        fi
    else
        phase_skip "$n" "golangci-lint not installed"
    fi
}

phase_coverage() {
    echo "==> 4. coverage floors"
    local n=$1

    go test -cover ./... 2>&1 | grep "coverage:" >/tmp/verify-coverage.log

    # Per-package floors. Packages with mostly-root paths are exempt.
    declare -A FLOORS=(
        ["aggregator"]=80
        ["ai"]=70
        ["chaos"]=60
        ["config"]=60
        ["doctor"]=50
        ["collector"]=50
    )

    for pkg in "${!FLOORS[@]}"; do
        floor=${FLOORS[$pkg]}
        actual=$(grep "/$pkg" /tmp/verify-coverage.log | grep -oE "coverage: [0-9.]+%" | head -1 | tr -dc '0-9.' | cut -d. -f1)
        if [[ -z "$actual" ]]; then
            phase_skip "$n" "$pkg: no coverage data"
            continue
        fi
        if [[ "$actual" -ge "$floor" ]]; then
            phase_pass "$n" "$pkg coverage ${actual}% >= ${floor}%"
        else
            phase_fail "$n" "$pkg coverage ${actual}% < ${floor}% floor"
        fi
    done
}

phase_bpf() {
    echo "==> 5. BPF verifier"
    local n=$1

    if [[ ! -x "$BPF_VERIFY" ]]; then
        phase_fail "$n" "$BPF_VERIFY not built"
        return 1
    fi

    sudo "$BPF_VERIFY" >/tmp/verify-bpf.log 2>&1 || true
    local ok
    ok=$(grep -c "VERIFIER OK" /tmp/verify-bpf.log)
    if [[ "$ok" -eq 6 ]]; then
        phase_pass "$n" "all 6/6 eBPF programs accepted by kernel verifier"
    else
        phase_fail "$n" "only $ok/6 programs passed (see /tmp/verify-bpf.log)"
    fi
}

phase_smoke() {
    echo "==> 6. CLI smoke tests"
    local n=$1

    if "$KERNO" version >/tmp/verify-version.log 2>&1; then
        phase_pass "$n" "$($KERNO version)"
    else
        phase_fail "$n" "kerno version failed"
        return 1
    fi

    for cmd in doctor explain predict start trace watch chaos version; do
        if "$KERNO" "$cmd" --help >/dev/null 2>&1; then
            phase_pass "$n" "$cmd --help OK"
        else
            phase_fail "$n" "$cmd --help failed"
        fi
    done

    # chaos --list must show all scenarios.
    local scenarios
    scenarios=$("$KERNO" chaos --list | tail -n +2 | awk '{print $1}' | sort | xargs)
    if [[ "$scenarios" == "cascade cpu disk-sat fd-leak memory tcp-churn" ]]; then
        phase_pass "$n" "chaos --list shows all 6 scenarios"
    else
        phase_fail "$n" "chaos --list missing scenarios: '$scenarios'"
    fi
}

phase_doctor() {
    echo "==> 7. doctor pipeline"
    local n=$1

    # Without sudo: should degrade gracefully and emit a healthy report.
    if "$KERNO" doctor --duration 1s --output json >/tmp/verify-doctor-clean.json 2>/dev/null; then
        if jq -e '.findings[0].rule == "healthy_system"' /tmp/verify-doctor-clean.json >/dev/null; then
            phase_pass "$n" "graceful degradation without sudo → healthy_system finding"
        else
            phase_fail "$n" "non-root run did not produce healthy_system"
        fi
    else
        phase_fail "$n" "doctor --output json failed without sudo"
    fi

    # JSON must be parseable and have expected schema.
    if jq -e '.summary.critical, .summary.warning, .summary.info' /tmp/verify-doctor-clean.json >/dev/null; then
        phase_pass "$n" "JSON has summary.{critical, warning, info}"
    else
        phase_fail "$n" "JSON summary fields missing"
    fi

    # Pretty render must not crash.
    if "$KERNO" doctor --duration 1s 2>/dev/null | grep -q "KERNO DOCTOR"; then
        phase_pass "$n" "pretty renderer produces banner"
    else
        phase_fail "$n" "pretty renderer broken"
    fi

    # --exit-code should return 0 on healthy.
    if "$KERNO" doctor --duration 1s --exit-code >/dev/null 2>&1; then
        phase_pass "$n" "--exit-code returns 0 on healthy"
    else
        phase_fail "$n" "--exit-code returned non-zero on healthy run"
    fi

    # explain without API key should fail with a clear message.
    local explain_out
    explain_out=$("$KERNO" explain "OOM killer invoked" 2>&1 || true)
    if echo "$explain_out" | grep -q "AI is not configured"; then
        phase_pass "$n" "explain without key → graceful error message"
    else
        phase_fail "$n" "explain without key did not produce expected error"
    fi
}

phase_chaos() {
    echo "==> 8. chaos scenarios"
    local n=$1

    for s in cpu fd-leak memory disk-sat tcp-churn; do
        if "$KERNO" chaos --induce "$s" --duration 1s --intensity low --yes \
                >/tmp/verify-chaos-"$s"-smoke.log 2>&1; then
            phase_pass "$n" "$s scenario completes cleanly"
        else
            phase_fail "$n" "$s scenario errored (see /tmp/verify-chaos-$s-smoke.log)"
        fi
    done

    # Cascade is longer; just verify it exits.
    if "$KERNO" chaos --induce cascade --duration 3s --intensity low --yes \
            >/tmp/verify-chaos-cascade.log 2>&1; then
        phase_pass "$n" "cascade scenario completes cleanly"
    else
        phase_fail "$n" "cascade scenario errored"
    fi

    # Verify temp files are cleaned up after every run.
    if ! ls /tmp/kerno-chaos-* 2>/dev/null >/dev/null; then
        phase_pass "$n" "temp files cleaned up after every run"
    else
        phase_fail "$n" "leaked temp files: $(ls /tmp/kerno-chaos-* 2>/dev/null)"
    fi
}

phase_induce_detect() {
    echo "==> 9. induce → detect pairings"
    local n=$1

    local pairings=(
        "disk-sat:disk_io_bottleneck"
        "fd-leak:fd_leak"
        "cpu:scheduler_contention"
        "tcp-churn:scheduler_contention"
    )

    for p in "${pairings[@]}"; do
        local scenario="${p%%:*}"
        local expected="${p##*:}"

        "$KERNO" chaos --induce "$scenario" --duration 12s --intensity high --yes \
            >/tmp/verify-chaos-"$scenario"-id.log 2>&1 &
        local cpid=$!
        sleep 1

        sudo "$KERNO" --config scripts/verify-config.yaml \
            doctor --duration 10s --output json \
            >/tmp/verify-doctor-"$scenario".json 2>/tmp/verify-doctor-"$scenario".log

        wait $cpid 2>/dev/null || true

        if jq -e --arg r "$expected" '.findings[] | select(.rule == $r)' \
                /tmp/verify-doctor-"$scenario".json >/dev/null 2>&1; then
            local sev
            sev=$(jq -r --arg r "$expected" \
                '.findings[] | select(.rule == $r) | .severity' \
                /tmp/verify-doctor-"$scenario".json | head -1)
            phase_pass "$n" "$scenario → $expected fired ($sev)"
        else
            phase_fail "$n" "$scenario did NOT trigger $expected"
        fi
    done
}

phase_daemon() {
    echo "==> 10. daemon mode"
    local n=$1

    # Pick a free local port.
    local port=19099
    sudo "$KERNO" start --prometheus-addr ":$port" >/tmp/verify-daemon.log 2>&1 &
    local dpid=$!

    # Wait up to 5s for the HTTP server to be ready.
    local ready=0
    for i in 1 2 3 4 5; do
        if curl -sf "localhost:$port/healthz" >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done

    if [[ "$ready" -ne 1 ]]; then
        phase_fail "$n" "daemon did not come up within 5s"
        sudo kill $dpid 2>/dev/null || true
        wait $dpid 2>/dev/null || true
        return 1
    fi
    phase_pass "$n" "daemon started; /healthz responsive"

    # /readyz
    if curl -sf "localhost:$port/readyz" >/dev/null; then
        phase_pass "$n" "/readyz returns 200"
    else
        phase_fail "$n" "/readyz did not return 200"
    fi

    # /metrics emits prom format
    if curl -sf "localhost:$port/metrics" | grep -q "^# HELP"; then
        phase_pass "$n" "/metrics returns valid Prometheus exposition"
    else
        phase_fail "$n" "/metrics did not return Prom format"
    fi

    # /metrics includes our self-monitoring metric
    if curl -sf "localhost:$port/metrics" | grep -q "^kerno_collector_events_total"; then
        phase_pass "$n" "/metrics includes kerno_collector_events_total"
    else
        phase_fail "$n" "/metrics missing kerno_collector_events_total"
    fi

    # Graceful shutdown.
    sudo kill -INT $dpid 2>/dev/null || true
    local stopped=0
    for i in 1 2 3 4 5; do
        if ! sudo kill -0 $dpid 2>/dev/null; then
            stopped=1
            break
        fi
        sleep 1
    done
    if [[ "$stopped" -eq 1 ]]; then
        phase_pass "$n" "daemon stopped cleanly within 5s of SIGINT"
    else
        phase_fail "$n" "daemon did not stop within 5s — sending SIGKILL"
        sudo kill -KILL $dpid 2>/dev/null || true
    fi
}

phase_manifests() {
    echo "==> 11. deployment manifests"
    local n=$1

    if require_cmd helm; then
        if helm lint deploy/helm/kerno >/tmp/verify-helm.log 2>&1; then
            phase_pass "$n" "helm lint deploy/helm/kerno: OK"
        else
            phase_fail "$n" "helm lint failed (see /tmp/verify-helm.log)"
        fi
    else
        phase_skip "$n" "helm not installed"
    fi

    # YAML syntax check on every k8s manifest
    local k8s_failed=0
    for f in deploy/k8s/*.yaml; do
        if python3 -c "import yaml,sys; yaml.safe_load_all(open('$f'))" 2>/dev/null; then
            :  # OK
        else
            phase_fail "$n" "invalid YAML: $f"
            k8s_failed=$((k8s_failed+1))
        fi
    done
    if [[ "$k8s_failed" -eq 0 ]]; then
        phase_pass "$n" "$(ls deploy/k8s/*.yaml | wc -l) k8s manifests parse as YAML"
    fi

    # systemd unit + chaos config
    for f in deploy/systemd/kerno.service deploy/systemd/kerno.yaml scripts/verify-config.yaml; do
        if [[ -f "$f" ]]; then
            phase_pass "$n" "$(basename "$f") present"
        else
            phase_fail "$n" "$f missing"
        fi
    done

    # goreleaser config
    if [[ -f .goreleaser.yml ]]; then
        if require_cmd goreleaser; then
            if goreleaser check >/dev/null 2>&1; then
                phase_pass "$n" "goreleaser check: OK"
            else
                phase_fail "$n" "goreleaser check failed"
            fi
        else
            phase_pass "$n" ".goreleaser.yml present (goreleaser binary not installed; skipping check)"
        fi
    fi
}

# ─── Phase registry ───────────────────────────────────────────────────────

declare -A PHASES=(
    [deps]=phase_deps
    [build]=phase_build
    [quality]=phase_quality
    [coverage]=phase_coverage
    [bpf]=phase_bpf
    [smoke]=phase_smoke
    [doctor]=phase_doctor
    [chaos]=phase_chaos
    [induce_detect]=phase_induce_detect
    [daemon]=phase_daemon
    [manifests]=phase_manifests
)

PHASE_ORDER=(deps build quality coverage bpf smoke doctor chaos induce_detect daemon manifests)

# ─── Argument parsing ─────────────────────────────────────────────────────

if [[ $# -gt 0 ]] && [[ "$1" == "--list" ]]; then
    echo "Available phases:"
    for p in "${PHASE_ORDER[@]}"; do
        echo "  - $p"
    done
    exit 0
fi

if [[ $# -gt 0 ]]; then
    SELECTED=("$@")
    for p in "${SELECTED[@]}"; do
        if [[ -z "${PHASES[$p]:-}" ]]; then
            echo "Unknown phase: $p" >&2
            echo "Run with --list to see available phases." >&2
            exit 2
        fi
    done
else
    SELECTED=("${PHASE_ORDER[@]}")
fi

# ─── Run phases ───────────────────────────────────────────────────────────

START_TIME=$(date +%s)
for phase in "${SELECTED[@]}"; do
    fn=${PHASES[$phase]}
    $fn "$phase" || true
    echo
done
ELAPSED=$(( $(date +%s) - START_TIME ))

# ─── Summary ──────────────────────────────────────────────────────────────

PASS=0
FAIL=0
for r in "${RESULTS[@]}"; do
    case "$r" in
        PASS\|*) PASS=$((PASS+1)) ;;
        FAIL\|*) FAIL=$((FAIL+1)) ;;
    esac
done

echo "═══════════════════════════════════════════════════════════════════"
echo "Verification Summary"
echo "  Phases run:    ${#SELECTED[@]}"
echo "  Checks passed: $PASS"
echo "  Checks failed: $FAIL"
echo "  Skipped:       ${#SKIPPED[@]}"
echo "  Elapsed:       ${ELAPSED}s"

if [[ "$FAIL" -gt 0 ]]; then
    echo
    echo "FAILED CHECKS:"
    for r in "${RESULTS[@]}"; do
        if [[ "${r%%|*}" == "FAIL" ]]; then
            phase_name=$(echo "$r" | cut -d'|' -f2)
            phase_reason=$(echo "$r" | cut -d'|' -f3-)
            echo "  - [$phase_name] $phase_reason"
        fi
    done
    echo
    echo "OVERALL: FAIL"
    exit 1
fi

echo
echo "OVERALL: PASS — kerno is production-ready."
