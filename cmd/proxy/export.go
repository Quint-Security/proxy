package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/export"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runExport handles: quint export [flags]
func runExport(args []string) {
	var (
		policyPath string
		last       string
		since      string
		until      string
		all        bool
		format     string
		output     string
		server     string
		tool       string
		verdict    string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		case "--last":
			i++
			if i < len(args) {
				last = args[i]
			}
		case "--since":
			i++
			if i < len(args) {
				since = args[i]
			}
		case "--until":
			i++
			if i < len(args) {
				until = args[i]
			}
		case "--all":
			all = true
		case "--format":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--output", "-o":
			i++
			if i < len(args) {
				output = args[i]
			}
		case "--server":
			i++
			if i < len(args) {
				server = args[i]
			}
		case "--tool":
			i++
			if i < len(args) {
				tool = args[i]
			}
		case "--verdict":
			i++
			if i < len(args) {
				verdict = args[i]
			}
		case "--help", "-h":
			printExportUsage()
			return
		}
	}

	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		fmt.Fprintf(os.Stderr, "quint export: unsupported format %q (use json or csv)\n", format)
		os.Exit(1)
	}

	if !all && last == "" && since == "" {
		printExportUsage()
		os.Exit(1)
	}

	// Resolve time range
	var sinceTime, untilTime string

	if all {
		// No time constraints
	} else if last != "" {
		dur, err := parseDuration(last)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quint export: invalid duration %q: %v\n", last, err)
			os.Exit(1)
		}
		sinceTime = time.Now().UTC().Add(-dur).Format("2006-01-02T15:04:05.000Z")
	} else if since != "" {
		t, err := parseDate(since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quint export: invalid date %q: %v\n", since, err)
			os.Exit(1)
		}
		sinceTime = t.Format("2006-01-02T15:04:05.000Z")
	}

	if until != "" {
		t, err := parseDate(until)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quint export: invalid date %q: %v\n", until, err)
			os.Exit(1)
		}
		// End of day
		untilTime = t.Add(24*time.Hour - time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	}

	// Load policy & open DB
	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint export: failed to load policy: %v\n", err)
		os.Exit(1)
	}
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.LoadKeyPair(dataDir, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint export: failed to load keys: %v\n", err)
		os.Exit(1)
	}
	if kp == nil {
		fmt.Fprintf(os.Stderr, "quint export: no keys found — run `quint setup` first\n")
		os.Exit(1)
	}

	db, err := audit.OpenDB(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint export: failed to open audit DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Query entries
	var entries []audit.Entry
	if all && server == "" && tool == "" && verdict == "" {
		entries, err = db.GetAll()
	} else {
		entries, err = db.GetRange(audit.RangeOpts{
			Since:      sinceTime,
			Until:      untilTime,
			ServerName: server,
			ToolName:   tool,
			Verdict:    verdict,
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint export: failed to query entries: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "quint export: no entries found for the specified range\n")
		os.Exit(1)
	}

	// Build bundle
	bundle, err := export.BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint export: failed to build bundle: %v\n", err)
		os.Exit(1)
	}

	// Output
	var out *os.File
	if output != "" {
		out, err = os.Create(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quint export: failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}

	switch format {
	case "json":
		data, err := export.ToJSON(bundle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quint export: failed to marshal bundle: %v\n", err)
			os.Exit(1)
		}
		out.Write(data)
		out.Write([]byte("\n"))
	case "csv":
		if err := export.WriteCSV(out, bundle); err != nil {
			fmt.Fprintf(os.Stderr, "quint export: failed to write CSV: %v\n", err)
			os.Exit(1)
		}
	}

	if output != "" {
		fmt.Fprintf(os.Stderr, "Exported %d entries to %s\n", len(entries), output)
	}
}

func printExportUsage() {
	fmt.Fprintf(os.Stderr, "Usage: quint export [flags]\n\n")
	fmt.Fprintf(os.Stderr, "Export a cryptographically signed audit proof bundle.\n\n")
	fmt.Fprintf(os.Stderr, "Time range (at least one required):\n")
	fmt.Fprintf(os.Stderr, "  --last <duration>    e.g. 7d, 24h, 30d\n")
	fmt.Fprintf(os.Stderr, "  --since <date>       e.g. 2026-02-20\n")
	fmt.Fprintf(os.Stderr, "  --until <date>       end date (default: now)\n")
	fmt.Fprintf(os.Stderr, "  --all                export everything\n\n")
	fmt.Fprintf(os.Stderr, "Filters:\n")
	fmt.Fprintf(os.Stderr, "  --server <name>      filter by server name\n")
	fmt.Fprintf(os.Stderr, "  --tool <name>        filter by tool name\n")
	fmt.Fprintf(os.Stderr, "  --verdict <v>        filter by verdict (allow, deny, flag)\n\n")
	fmt.Fprintf(os.Stderr, "Output:\n")
	fmt.Fprintf(os.Stderr, "  --format json|csv    output format (default: json)\n")
	fmt.Fprintf(os.Stderr, "  --output <file>      write to file (default: stdout)\n")
}

// parseDuration parses durations like "7d", "24h", "30d", "1h30m".
func parseDuration(s string) (time.Duration, error) {
	// Handle day suffix which time.ParseDuration doesn't support
	re := regexp.MustCompile(`^(\d+)d$`)
	if m := re.FindStringSubmatch(s); m != nil {
		days, _ := strconv.Atoi(m[1])
		return time.Duration(days) * 24 * time.Hour, nil
	}

	// Handle combinations like "7d12h"
	re = regexp.MustCompile(`^(\d+)d(\d+[hms].*)$`)
	if m := re.FindStringSubmatch(s); m != nil {
		days, _ := strconv.Atoi(m[1])
		rest, err := time.ParseDuration(m[2])
		if err != nil {
			return 0, err
		}
		return time.Duration(days)*24*time.Hour + rest, nil
	}

	return time.ParseDuration(s)
}

// parseDate parses date strings like "2026-02-20" or RFC3339.
func parseDate(s string) (time.Time, error) {
	// Try date-only first
	if !strings.Contains(s, "T") {
		return time.Parse("2006-01-02", s)
	}
	return time.Parse(time.RFC3339, s)
}
