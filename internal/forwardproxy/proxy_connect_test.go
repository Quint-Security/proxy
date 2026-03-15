package forwardproxy

import (
	"strings"
	"testing"

	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

func TestHandleConnect_MalformedHosts(t *testing.T) {
	hosts := []string{
		"otel.cline.bot:443",
		"",
		":443",
		":::443",
		"a]b[c:443",
		"very-" + strings.Repeat("long", 200) + ".domain.com:443",
		"localhost:0",
		"127.0.0.1:443",
		"[::1]:443",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			domain := intercept.StripPort(host)
			_ = domain
			_ = isPassthroughDomain(domain)
			_ = InferProvider(domain)
		})
	}
}
