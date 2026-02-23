package connect

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// TokenResult holds the result of an OAuth token exchange.
type TokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

// FlowOpts configures an OAuth PKCE flow.
type FlowOpts struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	Scopes       []string
	CallbackPort int
}

// RunOAuthFlow runs a full OAuth 2.0 PKCE authorization code flow.
func RunOAuthFlow(opts FlowOpts) (*TokenResult, error) {
	// Generate PKCE values
	verifierBytes := make([]byte, 64)
	rand.Read(verifierBytes)
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	stateBytes := make([]byte, 32)
	rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	// Start callback server
	listener, err := startListener(opts.CallbackPort)
	if err != nil {
		return nil, fmt.Errorf("start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)

	// Build auth URL
	authURL, _ := url.Parse(opts.AuthURL)
	q := authURL.Query()
	q.Set("client_id", opts.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	if len(opts.Scopes) > 0 {
		q.Set("scope", strings.Join(opts.Scopes, " "))
	}
	authURL.RawQuery = q.Encode()

	fmt.Printf("\nOpening browser for authorization...\n")
	fmt.Printf("If the browser doesn't open, visit:\n  %s\n\n", authURL.String())
	openBrowser(authURL.String())

	// Wait for callback
	code, receivedState, err := waitForCallback(listener)
	if err != nil {
		return nil, err
	}

	if receivedState != state {
		return nil, fmt.Errorf("OAuth state mismatch — possible CSRF attack")
	}

	// Exchange code for tokens
	fmt.Println("Exchanging authorization code for tokens...")
	return exchangeCode(opts.TokenURL, code, codeVerifier, redirectURI, opts.ClientID, opts.ClientSecret)
}

func startListener(fixedPort int) (net.Listener, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", fixedPort)
	return net.Listen("tcp", addr)
}

func waitForCallback(listener net.Listener) (code, state string, err error) {
	codeCh := make(chan string, 1)
	stateCh := make(chan string, 1)
	errCh := make(chan error, 1)

	srv := &http.Server{}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}

		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			desc := q.Get("error_description")
			if desc == "" {
				desc = e
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<h2>Authorization failed</h2><p>%s</p><p>You can close this tab.</p>", desc)
			errCh <- fmt.Errorf("OAuth authorization failed: %s", desc)
			return
		}

		c := q.Get("code")
		s := q.Get("state")
		if c == "" || s == "" {
			http.Error(w, "Missing code or state", 400)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<h2>Authorization successful!</h2><p>You can close this tab and return to the terminal.</p>")
		codeCh <- c
		stateCh <- s
	})

	go srv.Serve(listener)

	timeout := time.After(5 * time.Minute)
	select {
	case code = <-codeCh:
		state = <-stateCh
		srv.Close()
		return code, state, nil
	case err = <-errCh:
		srv.Close()
		return "", "", err
	case <-timeout:
		srv.Close()
		return "", "", fmt.Errorf("OAuth callback timed out after 5 minutes")
	}
}

func exchangeCode(tokenURL, code, codeVerifier, redirectURI, clientID, clientSecret string) (*TokenResult, error) {
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
	}
	if clientSecret != "" {
		params.Set("client_secret", clientSecret)
	}

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, body)
	}

	// Try JSON first, then form-encoded (GitHub returns form-encoded)
	var result TokenResult
	if err := json.Unmarshal(body, &result); err != nil {
		// Try form-encoded
		vals, _ := url.ParseQuery(string(body))
		result.AccessToken = vals.Get("access_token")
		result.RefreshToken = vals.Get("refresh_token")
		result.Scope = vals.Get("scope")
		result.TokenType = vals.Get("token_type")
		if result.TokenType == "" {
			result.TokenType = "bearer"
		}
	}

	if result.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in response: %s", body)
	}

	return &result, nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	}
	if cmd != nil {
		cmd.Run()
	}
}
