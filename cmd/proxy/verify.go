package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runVerify handles: quint-proxy verify [--id <n>] [--last <n>] [--all] [--chain]
func runVerify(args []string) {
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
