package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/connect"
	"github.com/Quint-Security/quint-proxy/internal/credential"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runConnect handles: quint-proxy connect <add|list|remove|status|providers> [options]
func runConnect(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy connect <add|list|remove|status|providers> [options]\n")
		os.Exit(1)
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "add":
		runConnectAdd(subargs)
	case "list":
		runConnectList(subargs)
	case "remove":
		runConnectRemove(subargs)
	case "status":
		runConnectStatus(subargs)
	case "providers":
		runConnectProviders()
	default:
		fmt.Fprintf(os.Stderr, "Unknown connect command: %s\n", subcmd)
		os.Exit(1)
	}
}

func openCredStore(policyPath string) (*credential.Store, string) {
	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load keys: %v\n", err)
		os.Exit(1)
	}

	encKey := credential.DeriveEncryptionKey(passphrase, kp.PrivateKey)
	store, err := credential.OpenStore(dataDir, encKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open credential store: %v\n", err)
		os.Exit(1)
	}
	return store, dataDir
}

func runConnectAdd(args []string) {
	var service, token, clientID, clientSecret, scopes, authURL, tokenURL, policyPath string
	var callbackPort int

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--token":
			i++
			if i < len(args) {
				token = args[i]
			}
		case "--client-id":
			i++
			if i < len(args) {
				clientID = args[i]
			}
		case "--client-secret":
			i++
			if i < len(args) {
				clientSecret = args[i]
			}
		case "--scopes":
			i++
			if i < len(args) {
				scopes = args[i]
			}
		case "--auth-url":
			i++
			if i < len(args) {
				authURL = args[i]
			}
		case "--token-url":
			i++
			if i < len(args) {
				tokenURL = args[i]
			}
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		default:
			if service == "" && !hasPrefix(args[i], "--") {
				service = args[i]
			}
		}
	}

	if service == "" {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy connect add <service> [--token <token> | --client-id <id>]\n")
		os.Exit(1)
	}

	store, _ := openCredStore(policyPath)
	defer store.Close()

	if token != "" {
		// Direct token storage
		store.Put(service, credential.StoreOpts{
			Provider:    service,
			AccessToken: token,
			Scopes:      scopes,
		})
		fmt.Printf("Credential stored for %q.\n", service)
		return
	}

	if clientID != "" {
		// OAuth PKCE flow
		provider := connect.GetProvider(service)
		if authURL == "" && provider != nil {
			authURL = provider.AuthURL
		}
		if tokenURL == "" && provider != nil {
			tokenURL = provider.TokenURL
		}
		if authURL == "" || tokenURL == "" {
			fmt.Fprintf(os.Stderr, "Unknown provider %q. Specify --auth-url and --token-url.\n", service)
			os.Exit(1)
		}

		var scopeList []string
		if scopes != "" {
			scopeList = strings.Split(scopes, ",")
		} else if provider != nil {
			scopeList = provider.DefaultScopes
		}

		result, err := connect.RunOAuthFlow(connect.FlowOpts{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			AuthURL:      authURL,
			TokenURL:     tokenURL,
			Scopes:       scopeList,
			CallbackPort: callbackPort,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "OAuth flow failed: %v\n", err)
			os.Exit(1)
		}

		var expiresAt string
		if result.ExpiresIn > 0 {
			expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
		}

		metadata := ""
		if clientID != "" {
			m, _ := json.Marshal(map[string]string{"client_id": clientID, "token_url": tokenURL})
			metadata = string(m)
		}

		store.Put(service, credential.StoreOpts{
			Provider:     service,
			AccessToken:  result.AccessToken,
			RefreshToken: result.RefreshToken,
			TokenType:    result.TokenType,
			Scopes:       result.Scope,
			ExpiresAt:    expiresAt,
			Metadata:     metadata,
		})

		fmt.Printf("\nOAuth credential stored for %q.\n", service)
		if result.Scope != "" {
			fmt.Printf("  Scopes: %s\n", result.Scope)
		}
		if expiresAt != "" {
			fmt.Printf("  Expires: %s\n", expiresAt)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "Specify --token <token> or --client-id <id>.\n")
	os.Exit(1)
}

func runConnectList(args []string) {
	var policyPath string
	for i := 0; i < len(args); i++ {
		if args[i] == "--policy" {
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		}
	}

	store, _ := openCredStore(policyPath)
	defer store.Close()

	creds, err := store.List()
	if err != nil || len(creds) == 0 {
		fmt.Println("No stored credentials. Use `quint-proxy connect add <service>` to add one.")
		return
	}

	fmt.Printf("%d stored credential(s):\n\n", len(creds))
	for _, c := range creds {
		expired := store.IsExpired(c.ID)
		status := "active"
		icon := "●"
		if expired {
			status = "EXPIRED"
			icon = "○"
		}
		fmt.Printf("  %s %s  provider=%s  [%s]  scopes=%s  updated=%s\n",
			icon, c.ID, c.Provider, status, orDefault(c.Scopes, "*"), c.UpdatedAt)
	}
}

func runConnectRemove(args []string) {
	var service, policyPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		default:
			if service == "" && !hasPrefix(args[i], "--") {
				service = args[i]
			}
		}
	}
	if service == "" {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy connect remove <service>\n")
		os.Exit(1)
	}

	store, _ := openCredStore(policyPath)
	defer store.Close()

	if store.Remove(service) {
		fmt.Printf("Credential for %q removed.\n", service)
	} else {
		fmt.Printf("No credential found for %q.\n", service)
	}
}

func runConnectStatus(args []string) {
	var service, policyPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		default:
			if service == "" && !hasPrefix(args[i], "--") {
				service = args[i]
			}
		}
	}
	if service == "" {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy connect status <service>\n")
		os.Exit(1)
	}

	store, _ := openCredStore(policyPath)
	defer store.Close()

	creds, _ := store.List()
	var found *credential.Credential
	for _, c := range creds {
		if c.ID == service {
			found = &c
			break
		}
	}
	if found == nil {
		fmt.Printf("No credential found for %q.\n", service)
		return
	}

	expired := store.IsExpired(service)
	status := "active"
	if expired {
		status = "EXPIRED"
	}

	fmt.Printf("Credential: %s\n", found.ID)
	fmt.Printf("  Provider:  %s\n", found.Provider)
	fmt.Printf("  Type:      %s\n", found.TokenType)
	fmt.Printf("  Scopes:    %s\n", orDefault(found.Scopes, "(all)"))
	fmt.Printf("  Status:    %s\n", status)
	expiresAt := "never"
	if found.ExpiresAt != nil {
		expiresAt = *found.ExpiresAt
	}
	fmt.Printf("  Expires:   %s\n", expiresAt)
	fmt.Printf("  Created:   %s\n", found.CreatedAt)
	fmt.Printf("  Updated:   %s\n", found.UpdatedAt)
}

func runConnectProviders() {
	fmt.Print("Known OAuth providers:\n\n")
	for key, p := range connect.Providers {
		fmt.Printf("  %s\n", key)
		fmt.Printf("    Name:   %s\n", p.Name)
		fmt.Printf("    Scopes: %s\n", strings.Join(p.DefaultScopes, ", "))
		fmt.Printf("    Docs:   %s\n\n", p.Docs)
	}
	fmt.Println("For unlisted providers, use --auth-url and --token-url with `quint-proxy connect add`.")
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
