package forwardproxy

import (
	"testing"

	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

func FuzzStripPort(f *testing.F) {
	f.Add("example.com:443")
	f.Add("otel.cline.bot:443")
	f.Add("")
	f.Add(":443")
	f.Add("host:")
	f.Add("[::1]:443")
	f.Fuzz(func(t *testing.T, host string) {
		_ = intercept.StripPort(host)
	})
}

func FuzzInferProvider(f *testing.F) {
	f.Add("api.anthropic.com")
	f.Add("api.openai.com")
	f.Add("otel.cline.bot")
	f.Add("")
	f.Fuzz(func(t *testing.T, domain string) {
		_ = InferProvider(domain)
	})
}

func FuzzIsPassthrough(f *testing.F) {
	f.Add("api.anthropic.com")
	f.Add("registry.npmjs.org")
	f.Add("otel.cline.bot")
	f.Add("")
	f.Fuzz(func(t *testing.T, domain string) {
		_ = isPassthroughDomain(domain)
	})
}
