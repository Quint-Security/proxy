package forwardproxy

import (
	"encoding/json"
	"strings"
)

// providerEntry maps a domain pattern to a canonical provider name.
type providerEntry struct {
	domain   string
	provider string
}

// providerMap maps specific API domains to canonical provider names.
// Checked in order — first match wins (exact match then suffix).
// These are high-confidence matches for known API endpoints.
var providerMap = []providerEntry{
	// Anthropic
	{"api.anthropic.com", "anthropic"},

	// OpenAI / ChatGPT
	{"api.openai.com", "openai"},
	{"chatgpt.com", "openai"},

	// Google (Gemini, Vertex AI, PaLM)
	{"generativelanguage.googleapis.com", "google"},
	{"api.gemini.google.com", "google"},
	{"aiplatform.googleapis.com", "google"},
	{"ai.google.dev", "google"},
	{"notebooks.googleapis.com", "google"},
	{"cloudcode-pa.googleapis.com", "google"},

	// Azure OpenAI (*.openai.azure.com) & Azure AI Services
	{"openai.azure.com", "azure-openai"},
	{"cognitive.microsoft.com", "azure-openai"},

	// AWS Bedrock & SageMaker
	{"bedrock-runtime.amazonaws.com", "aws-bedrock"},
	{"bedrock.amazonaws.com", "aws-bedrock"},
	{"sagemaker-runtime.amazonaws.com", "aws-sagemaker"},
	{"sagemaker.amazonaws.com", "aws-sagemaker"},

	// Meta Llama
	{"llama-api.meta.com", "meta"},
	{"www.llama.com", "meta"},

	// Cohere
	{"api.cohere.com", "cohere"},
	{"api.cohere.ai", "cohere"},

	// Mistral
	{"api.mistral.ai", "mistral"},

	// Together AI
	{"api.together.xyz", "together"},
	{"api.together.ai", "together"},

	// Replicate
	{"api.replicate.com", "replicate"},

	// Fireworks AI
	{"api.fireworks.ai", "fireworks"},

	// Groq
	{"api.groq.com", "groq"},

	// DeepSeek
	{"api.deepseek.com", "deepseek"},

	// Perplexity
	{"api.perplexity.ai", "perplexity"},

	// xAI (Grok)
	{"api.x.ai", "xai"},

	// AI21 Labs (Jamba, Jurassic)
	{"api.ai21.com", "ai21"},

	// Stability AI (Stable Diffusion)
	{"api.stability.ai", "stability"},

	// Hugging Face
	{"api-inference.huggingface.co", "huggingface"},
	{"huggingface.co", "huggingface"},

	// Cerebras
	{"api.cerebras.ai", "cerebras"},

	// SambaNova
	{"api.sambanova.ai", "sambanova"},
	{"fast-api.snova.ai", "sambanova"},

	// Lambda Labs
	{"api.lambdalabs.com", "lambda"},

	// Databricks (Mosaic, DBRX)
	{"adb-dp.azuredatabricks.net", "databricks"},

	// Cloudflare Workers AI
	{"api.cloudflare.com", "cloudflare"},
	{"gateway.ai.cloudflare.com", "cloudflare"},

	// DeepInfra
	{"api.deepinfra.com", "deepinfra"},

	// NVIDIA NIM
	{"integrate.api.nvidia.com", "nvidia"},
	{"build.nvidia.com", "nvidia"},

	// OpenRouter (aggregator)
	{"openrouter.ai", "openrouter"},

	// Anyscale / Endpoints
	{"api.endpoints.anyscale.com", "anyscale"},

	// Lepton AI
	{"api.lepton.ai", "lepton"},

	// Modal
	{"api.modal.com", "modal"},

	// Reka AI
	{"api.reka.ai", "reka"},

	// Voyage AI (embeddings)
	{"api.voyageai.com", "voyage"},

	// Writer AI
	{"api.writer.com", "writer"},

	// Aleph Alpha
	{"api.aleph-alpha.com", "aleph-alpha"},

	// Chinese providers
	{"open.bigmodel.cn", "zhipu"},           // Zhipu AI (GLM)
	{"aip.baidubce.com", "baidu"},           // Baidu (Ernie Bot)
	{"dashscope.aliyuncs.com", "alibaba"},   // Alibaba (Qwen/Tongyi)
	{"ark.cn-beijing.volces.com", "bytedance"}, // ByteDance (Doubao)
	{"api.moonshot.cn", "moonshot"},         // Moonshot AI (Kimi)
	{"api.lingyiwanwu.com", "01ai"},         // 01.AI (Yi)
	{"api.minimax.chat", "minimax"},         // MiniMax
	{"api.siliconflow.cn", "siliconflow"},   // SiliconFlow

	// Anthropic MCP proxy
	{"mcp-proxy.anthropic.com", "anthropic"},
}

// rootDomainMap provides fallback classification by matching the root/registrable
// domain. Checked only when providerMap has no match. This catches subdomains
// like console.anthropic.com, play.googleapis.com, etc.
var rootDomainMap = []providerEntry{
	// Major providers
	{"anthropic.com", "anthropic"},
	{"openai.com", "openai"},
	{"chatgpt.com", "openai"},
	{"googleapis.com", "google"},
	{"gemini.google.com", "google"},
	{"ai.google.dev", "google"},

	// Cloud platforms
	{"openai.azure.com", "azure-openai"},
	{"cognitive.microsoft.com", "azure-openai"},
	{"amazonaws.com", "aws"},
	{"databricks.com", "databricks"},

	// Open-source & inference providers
	{"cohere.com", "cohere"},
	{"cohere.ai", "cohere"},
	{"mistral.ai", "mistral"},
	{"together.xyz", "together"},
	{"together.ai", "together"},
	{"replicate.com", "replicate"},
	{"fireworks.ai", "fireworks"},
	{"groq.com", "groq"},
	{"deepseek.com", "deepseek"},
	{"perplexity.ai", "perplexity"},
	{"x.ai", "xai"},
	{"ai21.com", "ai21"},
	{"stability.ai", "stability"},
	{"huggingface.co", "huggingface"},
	{"cerebras.ai", "cerebras"},
	{"sambanova.ai", "sambanova"},
	{"snova.ai", "sambanova"},
	{"lambdalabs.com", "lambda"},
	{"deepinfra.com", "deepinfra"},
	{"nvidia.com", "nvidia"},
	{"openrouter.ai", "openrouter"},
	{"anyscale.com", "anyscale"},
	{"lepton.ai", "lepton"},
	{"modal.com", "modal"},
	{"reka.ai", "reka"},
	{"voyageai.com", "voyage"},
	{"writer.com", "writer"},
	{"aleph-alpha.com", "aleph-alpha"},
	{"meta.com", "meta"},
	{"llama.com", "meta"},

	// Chinese providers
	{"bigmodel.cn", "zhipu"},
	{"baidubce.com", "baidu"},
	{"aliyuncs.com", "alibaba"},
	{"volces.com", "bytedance"},
	{"moonshot.cn", "moonshot"},
	{"lingyiwanwu.com", "01ai"},
	{"minimax.chat", "minimax"},
	{"siliconflow.cn", "siliconflow"},

	// Aggregators / Gateways
	{"cloudflare.com", "cloudflare"},
	{"azuredatabricks.net", "databricks"},
}

// InferProvider maps a destination domain to a canonical AI provider name.
// Uses two-tier matching: specific API domains first, then root domain fallback.
// Returns empty string if the domain is not a recognized AI provider.
func InferProvider(domain string) string {
	domain = strings.ToLower(stripPort(domain))
	if domain == "" {
		return ""
	}

	// Tier 1: specific API domain match
	for _, entry := range providerMap {
		if domain == entry.domain || strings.HasSuffix(domain, "."+entry.domain) {
			return entry.provider
		}
	}

	// Tier 1.5: pattern-based matching for region-specific cloud services.
	// AWS: bedrock-runtime.{region}.amazonaws.com, sagemaker-runtime.{region}.amazonaws.com
	// Azure: {deployment}.openai.azure.com
	// Databricks: {workspace}.azuredatabricks.net, {workspace}.cloud.databricks.com
	if strings.HasSuffix(domain, ".amazonaws.com") {
		if strings.Contains(domain, "bedrock") {
			return "aws-bedrock"
		}
		if strings.Contains(domain, "sagemaker") {
			return "aws-sagemaker"
		}
	}
	if strings.HasSuffix(domain, ".openai.azure.com") {
		return "azure-openai"
	}
	if strings.HasSuffix(domain, ".azuredatabricks.net") || strings.HasSuffix(domain, ".cloud.databricks.com") {
		return "databricks"
	}

	// Tier 2: root domain fallback (catches any subdomain of a known provider)
	for _, entry := range rootDomainMap {
		if domain == entry.domain || strings.HasSuffix(domain, "."+entry.domain) {
			return entry.provider
		}
	}

	return ""
}

// InferProviderFromAction extracts the domain from an action string and classifies it.
// Action format: "http:{domain}:{verb}.{slug}" or "mcp:{server}:{tool}.{verb}"
// Returns the provider name and domain, or empty strings if unrecognizable.
func InferProviderFromAction(action string) (provider, domain string) {
	parts := strings.SplitN(action, ":", 3)
	if len(parts) < 2 {
		return "", ""
	}

	// For HTTP actions: "http:{domain}:{verb}.{slug}"
	if parts[0] == "http" && len(parts) >= 2 {
		domain = parts[1]
		return InferProvider(domain), domain
	}

	return "", ""
}

// ExtractModel extracts the "model" field from an API request body preview.
// Tries multiple JSON structures used by different providers.
// Returns empty string if the body is not valid JSON or has no model field.
func ExtractModel(bodyPreview string) string {
	if bodyPreview == "" {
		return ""
	}

	// Try standard {"model": "..."} (Anthropic, OpenAI, most providers)
	var standard struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal([]byte(bodyPreview), &standard); err == nil && standard.Model != "" {
		return standard.Model
	}

	// Try OpenAI responses API format {"model": "..."} nested or at top level
	// Also try {"model_id": "..."} used by some providers
	var alt struct {
		ModelID string `json:"model_id"`
	}
	if err := json.Unmarshal([]byte(bodyPreview), &alt); err == nil && alt.ModelID != "" {
		return alt.ModelID
	}

	return ""
}

// stripPort removes the port suffix from a host string.
func stripPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Only strip if what follows looks like a port number
		port := host[idx+1:]
		for _, c := range port {
			if c < '0' || c > '9' {
				return host
			}
		}
		return host[:idx]
	}
	return host
}
