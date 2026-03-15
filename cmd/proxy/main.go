package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "daemon":
			runDaemon(os.Args[2:])
			return
		case "watch":
			runWatch(os.Args[2:])
			return
		case "setup":
			runSetup(os.Args[2:])
			return
		case "env":
			runEnv(os.Args[2:])
			return
		case "status":
			runStatus(os.Args[2:])
			return
		case "uninstall":
			runUninstall(os.Args[2:])
			return
		case "--version", "version":
			fmt.Println(version)
			return
		default:
			fmt.Fprintf(os.Stderr, "quint: unknown command %q\n\n", os.Args[1])
			printUsage()
			os.Exit(1)
		}
	}

	printUsage()
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: quint <command> [flags]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  daemon      Run as system daemon (production mode)\n")
	fmt.Fprintf(os.Stderr, "  watch       Run in foreground (development mode)\n")
	fmt.Fprintf(os.Stderr, "  setup       Install and configure Quint (--env-only to refresh agents)\n")
	fmt.Fprintf(os.Stderr, "  uninstall   Remove Quint from this machine\n")
	fmt.Fprintf(os.Stderr, "  status      Show agent status\n")
	fmt.Fprintf(os.Stderr, "  env         Print env vars (--proxy for blanket HTTP_PROXY)\n")
	fmt.Fprintf(os.Stderr, "  version     Print version\n\n")
	fmt.Fprintf(os.Stderr, "Traffic routing:\n")
	fmt.Fprintf(os.Stderr, "  GUI apps (Cursor, VS Code)  → macOS system proxy (PAC file)\n")
	fmt.Fprintf(os.Stderr, "  CLI agents (claude, codex)  → Shell wrappers (auto-generated)\n")
	fmt.Fprintf(os.Stderr, "  Everything else              → Direct (no proxy)\n\n")
}

// httpGetQuick does a quick HTTP GET with a 2-second timeout.
// Used by setup to poll the daemon API.
func httpGetQuick(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	return client.Get(url)
}
