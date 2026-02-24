package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/export"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runVerify handles: quint verify [--id <n>] [--last <n>] [--all] [--chain]
// and:              quint verify export <file>
func runVerify(args []string) {
	// Check for "verify export <file>" subcommand
	if len(args) > 0 && args[0] == "export" {
		runVerifyExport(args[1:])
		return
	}

	var policyPath, idStr, lastStr string
	var all, chain bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		case "--id":
			i++
			if i < len(args) {
				idStr = args[i]
			}
		case "--last":
			i++
			if i < len(args) {
				lastStr = args[i]
			}
		case "--all":
			all = true
		case "--chain":
			chain = true
		}
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	db, err := audit.OpenDB(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open audit DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	var entries []audit.Entry

	if idStr != "" {
		id, _ := strconv.ParseInt(idStr, 10, 64)
		e, err := db.GetByID(id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Entry not found: %v\n", err)
			os.Exit(1)
		}
		entries = []audit.Entry{*e}
	} else if all {
		entries, err = db.GetAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read entries: %v\n", err)
			os.Exit(1)
		}
		chain = true // --all implies --chain
	} else {
		n := 20
		if lastStr != "" {
			n, _ = strconv.Atoi(lastStr)
		}
		entries, err = db.GetLast(n)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read entries: %v\n", err)
			os.Exit(1)
		}
	}

	if len(entries) == 0 {
		fmt.Println("No entries to verify.")
		return
	}

	result := audit.VerifyAll(entries, chain)

	for _, e := range result.Errors {
		fmt.Printf("  %s\n", e)
	}

	fmt.Printf("\nSignatures: %d checked, %d valid, %d invalid\n", result.Checked, result.SigValid, result.SigInvalid)

	if chain || all {
		if result.ChainValid+result.ChainBroken > 0 {
			fmt.Printf("Chain:      %d links checked, %d valid, %d broken\n", result.ChainValid+result.ChainBroken, result.ChainValid, result.ChainBroken)
		} else {
			fmt.Println("Chain:      no chain data (legacy entries)")
		}
	}

	if result.SigInvalid > 0 || result.ChainBroken > 0 {
		os.Exit(1)
	}
}

// runVerifyExport handles: quint verify export <file>
// Standalone offline verification of an export bundle.
func runVerifyExport(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: quint verify export <file>\n")
		os.Exit(1)
	}

	filePath := args[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read bundle file: %v\n", err)
		os.Exit(1)
	}

	bundle, err := export.ParseBundle(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse bundle: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Verifying bundle: %s\n", filePath)
	fmt.Printf("  Format:     %s v%d\n", bundle.Format, bundle.Version)
	fmt.Printf("  Exported:   %s\n", bundle.ExportedAt)
	fmt.Printf("  Entries:    %d\n", len(bundle.Entries))
	if bundle.Range.From != "" {
		fmt.Printf("  Range:      %s to %s\n", bundle.Range.From, bundle.Range.To)
	}
	fmt.Println()

	result := export.VerifyBundle(bundle)

	for _, e := range result.Errors {
		fmt.Printf("  %s\n", e)
	}

	// Bundle signature
	if result.BundleSignatureValid {
		fmt.Printf("Bundle signature: VALID\n")
	} else {
		fmt.Printf("Bundle signature: INVALID\n")
	}

	// Entry signatures
	fmt.Printf("Entry signatures: %d/%d valid\n", result.SignaturesValid, result.SignaturesChecked)

	// Chain
	if result.ChainLinksChecked > 0 {
		if result.ChainValid {
			fmt.Printf("Chain: VALID (%d/%d entries)\n", len(bundle.Entries), len(bundle.Entries))
		} else {
			fmt.Printf("Chain: BROKEN (%d breaks in %d links)\n", result.ChainBreaks, result.ChainLinksChecked)
		}
	} else if len(bundle.Entries) <= 1 {
		fmt.Printf("Chain: N/A (single entry)\n")
	} else {
		fmt.Printf("Chain: no chain data (legacy entries)\n")
	}

	if !result.BundleSignatureValid || result.SignaturesInvalid > 0 || result.ChainBreaks > 0 {
		fmt.Println("\nVerification FAILED")
		os.Exit(1)
	}

	fmt.Println("\nNo breaks found")
}
