package relay

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"sync"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

const maxLineSize = 10 * 1024 * 1024 // 10 MB for large MCP payloads

// Callbacks configures how the relay processes messages.
type Callbacks struct {
	// OnParentMessage is called for each line read from stdin (parent → child direction).
	// It returns the line to forward to the child, or "" to suppress forwarding.
	OnParentMessage func(line string) string
	// OnChildMessage is called for each line read from the child's stdout (child → parent direction).
	// It returns the line to forward to the parent, or "" to suppress forwarding.
	OnChildMessage func(line string) string
}

// Relay manages the child MCP server process and pipes stdin/stdout through callbacks.
type Relay struct {
	cmd       *exec.Cmd
	childIn   io.WriteCloser
	callbacks Callbacks
	done      chan struct{}
	mu        sync.Mutex
}

// New creates a relay that will spawn the given command with args.
func New(command string, args []string, cb Callbacks) *Relay {
	return &Relay{
		cmd:       exec.Command(command, args...),
		callbacks: cb,
		done:      make(chan struct{}),
	}
}

// Start spawns the child process and begins piping messages.
// It blocks until the child exits or an error occurs.
// Returns the child's exit code (0 if signal-killed).
func (r *Relay) Start() int {
	r.cmd.Stderr = os.Stderr
	r.cmd.Env = os.Environ()

	var err error
	r.childIn, err = r.cmd.StdinPipe()
	if err != nil {
		qlog.Error("failed to create child stdin pipe: %v", err)
		return 1
	}

	childOut, err := r.cmd.StdoutPipe()
	if err != nil {
		qlog.Error("failed to create child stdout pipe: %v", err)
		return 1
	}

	if err := r.cmd.Start(); err != nil {
		qlog.Error("failed to start child process: %v", err)
		return 1
	}

	var wg sync.WaitGroup

	// Read from child stdout → parent stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(childOut)
		scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)
		for scanner.Scan() {
			line := scanner.Text()
			if r.callbacks.OnChildMessage != nil {
				line = r.callbacks.OnChildMessage(line)
			}
			if line != "" {
				r.sendToParent(line)
			}
		}
		if err := scanner.Err(); err != nil {
			qlog.Error("child stdout read error: %v", err)
		}
	}()

	// Read from parent stdin → child stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)
		for scanner.Scan() {
			line := scanner.Text()
			if r.callbacks.OnParentMessage != nil {
				line = r.callbacks.OnParentMessage(line)
			}
			if line != "" {
				r.sendToChild(line)
			}
		}
		if err := scanner.Err(); err != nil {
			qlog.Error("parent stdin read error: %v", err)
		}
		// Parent closed stdin — close child's stdin so it can finish
		r.childIn.Close()
	}()

	// Wait for child to exit
	err = r.cmd.Wait()
	close(r.done)
	wg.Wait()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

// SendToParent writes a line to the parent's stdout (the JSON-RPC pipe).
func (r *Relay) sendToParent(line string) {
	// stdout is the JSON-RPC pipe — must be atomic per line
	os.Stdout.WriteString(line + "\n")
}

// SendToChild writes a line to the child process's stdin.
func (r *Relay) sendToChild(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.childIn != nil {
		io.WriteString(r.childIn, line+"\n")
	}
}

// SendResponseToParent sends a synthesized response (e.g., deny) to the parent.
func (r *Relay) SendResponseToParent(line string) {
	r.sendToParent(line)
}

// Stop sends SIGKILL to the child process.
func (r *Relay) Stop() {
	if r.cmd.Process != nil {
		r.cmd.Process.Kill()
	}
}

// Done returns a channel that is closed when the child process exits.
func (r *Relay) Done() <-chan struct{} {
	return r.done
}
