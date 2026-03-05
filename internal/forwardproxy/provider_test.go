package forwardproxy

import "testing"

func TestInferProvider(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		// Tier 1: specific API domains — major providers
		{"api.anthropic.com", "anthropic"},
		{"mcp-proxy.anthropic.com", "anthropic"},
		{"api.openai.com", "openai"},
		{"chatgpt.com", "openai"},
		{"generativelanguage.googleapis.com", "google"},
		{"api.gemini.google.com", "google"},
		{"aiplatform.googleapis.com", "google"},
		{"ai.google.dev", "google"},

		// Tier 1: inference providers
		{"api.cohere.com", "cohere"},
		{"api.cohere.ai", "cohere"},
		{"api.mistral.ai", "mistral"},
		{"api.together.xyz", "together"},
		{"api.together.ai", "together"},
		{"api.replicate.com", "replicate"},
		{"api.fireworks.ai", "fireworks"},
		{"api.groq.com", "groq"},
		{"api.deepseek.com", "deepseek"},
		{"api.perplexity.ai", "perplexity"},
		{"api.x.ai", "xai"},
		{"api.ai21.com", "ai21"},
		{"api.stability.ai", "stability"},
		{"api-inference.huggingface.co", "huggingface"},
		{"api.cerebras.ai", "cerebras"},
		{"api.sambanova.ai", "sambanova"},
		{"fast-api.snova.ai", "sambanova"},
		{"api.lambdalabs.com", "lambda"},
		{"api.deepinfra.com", "deepinfra"},
		{"integrate.api.nvidia.com", "nvidia"},
		{"build.nvidia.com", "nvidia"},
		{"openrouter.ai", "openrouter"},
		{"api.endpoints.anyscale.com", "anyscale"},
		{"api.lepton.ai", "lepton"},
		{"api.reka.ai", "reka"},
		{"api.voyageai.com", "voyage"},
		{"api.writer.com", "writer"},
		{"api.aleph-alpha.com", "aleph-alpha"},
		{"llama-api.meta.com", "meta"},

		// Tier 1: Chinese providers
		{"open.bigmodel.cn", "zhipu"},
		{"aip.baidubce.com", "baidu"},
		{"dashscope.aliyuncs.com", "alibaba"},
		{"ark.cn-beijing.volces.com", "bytedance"},
		{"api.moonshot.cn", "moonshot"},
		{"api.lingyiwanwu.com", "01ai"},
		{"api.minimax.chat", "minimax"},
		{"api.siliconflow.cn", "siliconflow"},

		// Tier 1.5: cloud platform region-specific patterns
		{"bedrock-runtime.us-east-1.amazonaws.com", "aws-bedrock"},
		{"bedrock-runtime.eu-west-1.amazonaws.com", "aws-bedrock"},
		{"sagemaker-runtime.us-west-2.amazonaws.com", "aws-sagemaker"},
		{"my-deployment.openai.azure.com", "azure-openai"},
		{"my-workspace.cloud.databricks.com", "databricks"},
		{"my-workspace.azuredatabricks.net", "databricks"},

		// Tier 2: root domain fallback (the user's actual cases)
		{"console.anthropic.com", "anthropic"},
		{"bedrock.anthropic.com", "anthropic"},
		{"play.googleapis.com", "google"},
		{"storage.googleapis.com", "google"},
		{"www.chatgpt.com", "openai"},

		// Tier 2: root domain catches subdomains of new providers
		{"docs.mistral.ai", "mistral"},
		{"hub.huggingface.co", "huggingface"},
		{"some.deepseek.com", "deepseek"},

		// Case insensitive
		{"API.ANTHROPIC.COM", "anthropic"},
		{"Api.OpenAI.Com", "openai"},
		{"CHATGPT.COM", "openai"},
		{"API.GROQ.COM", "groq"},

		// With port
		{"api.anthropic.com:443", "anthropic"},
		{"chatgpt.com:443", "openai"},

		// Subdomain suffix match
		{"us.api.anthropic.com", "anthropic"},

		// Unknown domains (should NOT match)
		{"example.com", ""},
		{"google.com", ""},
		{"api.unknown.io", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := InferProvider(tt.domain)
			if got != tt.want {
				t.Errorf("InferProvider(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestInferProviderFromAction(t *testing.T) {
	tests := []struct {
		action       string
		wantProvider string
		wantDomain   string
	}{
		{"http:chatgpt.com:post.responses", "openai", "chatgpt.com"},
		{"http:api.anthropic.com:post.messages", "anthropic", "api.anthropic.com"},
		{"http:play.googleapis.com:post.upload", "google", "play.googleapis.com"},
		{"http:example.com:get.index", "", "example.com"},
		{"mcp:server:tool.call", "", ""},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			provider, domain := InferProviderFromAction(tt.action)
			if provider != tt.wantProvider {
				t.Errorf("provider = %q, want %q", provider, tt.wantProvider)
			}
			if domain != tt.wantDomain {
				t.Errorf("domain = %q, want %q", domain, tt.wantDomain)
			}
		})
	}
}

func TestExtractModel(t *testing.T) {
	tests := []struct {
		name        string
		bodyPreview string
		want        string
	}{
		{"anthropic model", `{"model":"claude-sonnet-4-20250514","messages":[]}`, "claude-sonnet-4-20250514"},
		{"openai model", `{"model":"gpt-4o","temperature":0.7}`, "gpt-4o"},
		{"model_id fallback", `{"model_id":"custom-model-v2"}`, "custom-model-v2"},
		{"no model field", `{"messages":[{"role":"user"}]}`, ""},
		{"invalid json", `not json at all`, ""},
		{"empty string", "", ""},
		{"truncated json", `{"model":"claude-sonn...`, ""},
		{"model is empty", `{"model":""}`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractModel(tt.bodyPreview)
			if got != tt.want {
				t.Errorf("ExtractModel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"api.anthropic.com:443", "api.anthropic.com"},
		{"api.openai.com:8080", "api.openai.com"},
		{"api.anthropic.com", "api.anthropic.com"},
		{"[::1]:443", "[::1]"}, // IPv6 with port — strips port
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := stripPort(tt.host)
			if got != tt.want {
				t.Errorf("stripPort(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
