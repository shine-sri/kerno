// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/lowplane/kerno/internal/bpf"
)

func newTraceSyscallCmd() *cobra.Command {
	var (
		filter   string
		pid      int
		top      int
		duration time.Duration
		output   string
	)

	cmd := &cobra.Command{
		Use:   "syscall",
		Short: "Trace syscall latency events",
		Long: `Stream real-time syscall latency events from the kernel via eBPF.
Events include PID, process name, syscall number, latency, and return value.

Use --top to display a refreshing top-N view sorted by latency percentile.`,
		Example: `  # Stream all syscall events
  sudo kerno trace syscall

  # Filter by process
  sudo kerno trace syscall --pid 1234

  # Filter by syscall name
  sudo kerno trace syscall --filter read

  # Top 10 by p99 latency, refreshing every 1s
  sudo kerno trace syscall --top 10`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				output = resolveOutput(cmd)
			}
			return runTraceSyscall(cmd.Context(), traceSyscallOpts{
				filter:   filter,
				pid:      pid,
				top:      top,
				duration: duration,
				output:   output,
			})
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&filter, "filter", "", "filter by syscall name or number")
	flags.IntVar(&pid, "pid", 0, "filter by process ID (0 = all)")
	flags.IntVar(&top, "top", 0, "show top N syscalls by latency (0 = stream mode)")
	flags.DurationVar(&duration, "duration", 0, "run for this duration then exit (0 = indefinite)")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json")

	return cmd
}

type traceSyscallOpts struct {
	filter   string
	pid      int
	top      int
	duration time.Duration
	output   string
}

func runTraceSyscall(ctx context.Context, opts traceSyscallOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()
	loader := bpf.NewSyscallLatencyLoader(logger)

	closer, err := loader.Load()
	if err != nil {
		return fmt.Errorf("loading syscall_latency eBPF program: %w", err)
	}
	defer closer.Close()

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if opts.duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.duration)
		defer cancel()
	}

	events, err := loader.Events(ctx)
	if err != nil {
		return fmt.Errorf("reading events: %w", err)
	}

	if opts.top > 0 {
		return traceSyscallTop(ctx, events, opts)
	}
	return traceSyscallStream(ctx, events, opts)
}

// matchSyscallFilter checks if a syscall event matches the --filter flag.
func matchSyscallFilter(event *bpf.SyscallEvent, filter string) bool {
	if filter == "" {
		return true
	}
	// Match by syscall number.
	if nr, err := strconv.Atoi(filter); err == nil {
		return int(event.SyscallNr) == nr
	}
	// Match by syscall name (case-insensitive).
	name := syscallName(event.SyscallNr)
	return strings.EqualFold(name, filter)
}

func traceSyscallStream(ctx context.Context, events <-chan bpf.RawEvent, opts traceSyscallOpts) error {
	encoder := json.NewEncoder(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			return nil
		case raw, ok := <-events:
			if !ok {
				return nil
			}
			event, err := bpf.DecodeSyscallEvent(raw.Data)
			if err != nil {
				slog.Default().Debug("decode error", "error", err)
				continue
			}

			if opts.pid != 0 && int(event.PID) != opts.pid {
				continue
			}
			if !matchSyscallFilter(event, opts.filter) {
				continue
			}

			if opts.output == "json" {
				encoder.Encode(syscallEventJSON(event))
			} else {
				fmt.Fprintf(os.Stdout, "[%s] PID=%-6d COMM=%-16s SYSCALL=%-16s LATENCY=%-10s RET=%d\n",
					time.Now().Format("15:04:05"),
					event.PID,
					event.CommString(),
					syscallName(event.SyscallNr),
					formatLatency(event.Latency()),
					event.Ret,
				)
			}
		}
	}
}

// syscallTopEntry aggregates latency data for a (syscall, comm) key.
type syscallTopEntry struct {
	SyscallNr uint32
	Name      string
	Comm      string
	Count     uint64
	Latencies []time.Duration
}

func traceSyscallTop(ctx context.Context, events <-chan bpf.RawEvent, opts traceSyscallOpts) error {
	agg := make(map[topKey]*syscallTopEntry)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	const maxSamples = 10000

	for {
		select {
		case <-ctx.Done():
			return nil
		case raw, ok := <-events:
			if !ok {
				return nil
			}
			event, err := bpf.DecodeSyscallEvent(raw.Data)
			if err != nil {
				continue
			}
			if opts.pid != 0 && int(event.PID) != opts.pid {
				continue
			}
			if !matchSyscallFilter(event, opts.filter) {
				continue
			}

			key := topKey{nr: event.SyscallNr, comm: event.CommString()}
			e, ok := agg[key]
			if !ok {
				e = &syscallTopEntry{
					SyscallNr: event.SyscallNr,
					Name:      syscallName(event.SyscallNr),
					Comm:      key.comm,
				}
				agg[key] = e
			}
			e.Count++
			if len(e.Latencies) < maxSamples {
				e.Latencies = append(e.Latencies, event.Latency())
			}

		case <-ticker.C:
			renderSyscallTop(agg, opts.top)
			// Reset for next window.
			agg = make(map[topKey]*syscallTopEntry)
		}
	}
}

type topKey struct {
	nr   uint32
	comm string
}

func renderSyscallTop(agg map[topKey]*syscallTopEntry, n int) {
	entries := make([]*syscallTopEntry, 0, len(agg))
	for _, e := range agg {
		entries = append(entries, e)
	}

	// Sort by p99 descending.
	sort.Slice(entries, func(i, j int) bool {
		return percentile(entries[i].Latencies, 99) > percentile(entries[j].Latencies, 99)
	})

	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}

	if isTerminal() {
		fmt.Print("\033[H\033[2J") // clear screen
	}

	fmt.Printf("[%s] Syscall Latency Top — %d entries (last 1s)\n",
		time.Now().Format("15:04:05"), len(entries))
	fmt.Printf("%-16s %-16s %8s %10s %10s %10s\n",
		"SYSCALL", "PROCESS", "COUNT", "P50", "P95", "P99")
	fmt.Println(strings.Repeat("─", 78))

	for _, e := range entries {
		fmt.Printf("%-16s %-16s %8d %10s %10s %10s\n",
			e.Name, e.Comm, e.Count,
			formatLatency(percentile(e.Latencies, 50)),
			formatLatency(percentile(e.Latencies, 95)),
			formatLatency(percentile(e.Latencies, 99)),
		)
	}
	fmt.Println()
}

// percentile computes the p-th percentile from a slice of durations.
func percentile(data []time.Duration, p int) time.Duration {
	if len(data) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(data))
	copy(sorted, data)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := len(sorted) * p / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

type syscallEventOut struct {
	Timestamp string `json:"timestamp"`
	PID       uint32 `json:"pid"`
	TID       uint32 `json:"tid"`
	Comm      string `json:"comm"`
	Syscall   string `json:"syscall"`
	SyscallNr uint32 `json:"syscallNr"`
	LatencyNs uint64 `json:"latencyNs"`
	Ret       uint32 `json:"ret"`
}

func syscallEventJSON(e *bpf.SyscallEvent) syscallEventOut {
	return syscallEventOut{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		PID:       e.PID,
		TID:       e.TID,
		Comm:      e.CommString(),
		Syscall:   syscallName(e.SyscallNr),
		SyscallNr: e.SyscallNr,
		LatencyNs: e.LatencyNs,
		Ret:       e.Ret,
	}
}

// syscallName returns the name for a Linux syscall number on amd64.
// This covers the most common syscalls; unknown numbers return "syscall_NR".
func syscallName(nr uint32) string {
	names := map[uint32]string{
		0: "read", 1: "write", 2: "open", 3: "close",
		4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
		8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
		12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
		16: "ioctl", 17: "pread64", 18: "pwrite64",
		19: "readv", 20: "writev", 21: "access",
		22: "pipe", 23: "select", 24: "sched_yield",
		32: "dup", 33: "dup2",
		39: "getpid", 41: "socket", 42: "connect", 43: "accept",
		44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg",
		48: "shutdown", 49: "bind", 50: "listen",
		56: "clone", 57: "fork", 58: "vfork", 59: "execve",
		60: "exit", 61: "wait4", 62: "kill",
		72: "fcntl", 73: "flock", 74: "fsync", 75: "fdatasync",
		77: "ftruncate", 78: "getdents",
		79: "getcwd", 80: "chdir", 82: "rename",
		83: "mkdir", 84: "rmdir", 85: "creat", 86: "link", 87: "unlink",
		89: "readlink", 90: "chmod", 92: "chown",
		137: "statfs", 186: "gettid",
		202: "futex", 217: "getdents64",
		231: "exit_group", 232: "epoll_wait",
		257: "openat", 262: "newfstatat",
		268: "fchmodat", 280: "utimensat",
		288: "accept4", 290: "sendmmsg",
		302: "prlimit64", 318: "getrandom",
		332: "statx",
		435: "clone3",
	}
	if name, ok := names[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}
