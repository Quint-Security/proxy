package forwardproxy

// ProviderMeta holds display metadata for a known AI provider.
type ProviderMeta struct {
	// ID is the canonical provider identifier (e.g. "anthropic", "openai").
	ID string `json:"id"`
	// DisplayName is the human-readable provider name (e.g. "Anthropic", "OpenAI").
	DisplayName string `json:"display_name"`
	// Color is a hex color for dashboard badges/icons (e.g. "#D97757").
	Color string `json:"color"`
	// IconClass is an identifier the dashboard uses to render the right logo.
	// Maps to SVG paths or icon components on the frontend.
	IconClass string `json:"icon_class"`
	// Category groups providers: "frontier", "cloud", "open-source", "inference", "aggregator", "chinese", "specialized".
	Category string `json:"category"`
}

// providerMetaMap maps canonical provider IDs to their display metadata.
var providerMetaMap = map[string]ProviderMeta{
	// --- Frontier model providers ---
	"anthropic": {
		ID: "anthropic", DisplayName: "Anthropic", Color: "#D97757",
		IconClass: "anthropic", Category: "frontier",
	},
	"openai": {
		ID: "openai", DisplayName: "OpenAI", Color: "#10A37F",
		IconClass: "openai", Category: "frontier",
	},
	"google": {
		ID: "google", DisplayName: "Google", Color: "#4285F4",
		IconClass: "google", Category: "frontier",
	},
	"meta": {
		ID: "meta", DisplayName: "Meta", Color: "#0668E1",
		IconClass: "meta", Category: "frontier",
	},
	"mistral": {
		ID: "mistral", DisplayName: "Mistral", Color: "#F54E42",
		IconClass: "mistral", Category: "frontier",
	},
	"cohere": {
		ID: "cohere", DisplayName: "Cohere", Color: "#39594D",
		IconClass: "cohere", Category: "frontier",
	},
	"ai21": {
		ID: "ai21", DisplayName: "AI21 Labs", Color: "#4B44CE",
		IconClass: "ai21", Category: "frontier",
	},
	"xai": {
		ID: "xai", DisplayName: "xAI", Color: "#FFFFFF",
		IconClass: "xai", Category: "frontier",
	},
	"deepseek": {
		ID: "deepseek", DisplayName: "DeepSeek", Color: "#4D6BFE",
		IconClass: "deepseek", Category: "frontier",
	},
	"reka": {
		ID: "reka", DisplayName: "Reka AI", Color: "#6366F1",
		IconClass: "reka", Category: "frontier",
	},

	// --- Cloud platforms ---
	"azure-openai": {
		ID: "azure-openai", DisplayName: "Azure OpenAI", Color: "#0078D4",
		IconClass: "azure", Category: "cloud",
	},
	"aws-bedrock": {
		ID: "aws-bedrock", DisplayName: "AWS Bedrock", Color: "#FF9900",
		IconClass: "aws", Category: "cloud",
	},
	"aws-sagemaker": {
		ID: "aws-sagemaker", DisplayName: "AWS SageMaker", Color: "#FF9900",
		IconClass: "aws", Category: "cloud",
	},
	"databricks": {
		ID: "databricks", DisplayName: "Databricks", Color: "#FF3621",
		IconClass: "databricks", Category: "cloud",
	},
	"cloudflare": {
		ID: "cloudflare", DisplayName: "Cloudflare Workers AI", Color: "#F6821F",
		IconClass: "cloudflare", Category: "cloud",
	},

	// --- Inference providers ---
	"together": {
		ID: "together", DisplayName: "Together AI", Color: "#0EA5E9",
		IconClass: "together", Category: "inference",
	},
	"replicate": {
		ID: "replicate", DisplayName: "Replicate", Color: "#262626",
		IconClass: "replicate", Category: "inference",
	},
	"fireworks": {
		ID: "fireworks", DisplayName: "Fireworks AI", Color: "#FF6B35",
		IconClass: "fireworks", Category: "inference",
	},
	"groq": {
		ID: "groq", DisplayName: "Groq", Color: "#F55036",
		IconClass: "groq", Category: "inference",
	},
	"perplexity": {
		ID: "perplexity", DisplayName: "Perplexity", Color: "#20B2AA",
		IconClass: "perplexity", Category: "inference",
	},
	"cerebras": {
		ID: "cerebras", DisplayName: "Cerebras", Color: "#0066FF",
		IconClass: "cerebras", Category: "inference",
	},
	"sambanova": {
		ID: "sambanova", DisplayName: "SambaNova", Color: "#FF6600",
		IconClass: "sambanova", Category: "inference",
	},
	"lambda": {
		ID: "lambda", DisplayName: "Lambda Labs", Color: "#8B5CF6",
		IconClass: "lambda", Category: "inference",
	},
	"deepinfra": {
		ID: "deepinfra", DisplayName: "DeepInfra", Color: "#1E40AF",
		IconClass: "deepinfra", Category: "inference",
	},
	"nvidia": {
		ID: "nvidia", DisplayName: "NVIDIA NIM", Color: "#76B900",
		IconClass: "nvidia", Category: "inference",
	},
	"anyscale": {
		ID: "anyscale", DisplayName: "Anyscale", Color: "#00BCD4",
		IconClass: "anyscale", Category: "inference",
	},
	"lepton": {
		ID: "lepton", DisplayName: "Lepton AI", Color: "#7C3AED",
		IconClass: "lepton", Category: "inference",
	},
	"modal": {
		ID: "modal", DisplayName: "Modal", Color: "#22C55E",
		IconClass: "modal", Category: "inference",
	},

	// --- Aggregators ---
	"openrouter": {
		ID: "openrouter", DisplayName: "OpenRouter", Color: "#6366F1",
		IconClass: "openrouter", Category: "aggregator",
	},

	// --- Specialized providers ---
	"stability": {
		ID: "stability", DisplayName: "Stability AI", Color: "#A855F7",
		IconClass: "stability", Category: "specialized",
	},
	"huggingface": {
		ID: "huggingface", DisplayName: "Hugging Face", Color: "#FFD21E",
		IconClass: "huggingface", Category: "specialized",
	},
	"voyage": {
		ID: "voyage", DisplayName: "Voyage AI", Color: "#0EA5E9",
		IconClass: "voyage", Category: "specialized",
	},
	"writer": {
		ID: "writer", DisplayName: "Writer", Color: "#000000",
		IconClass: "writer", Category: "specialized",
	},
	"aleph-alpha": {
		ID: "aleph-alpha", DisplayName: "Aleph Alpha", Color: "#5046E5",
		IconClass: "aleph-alpha", Category: "specialized",
	},

	// --- Chinese providers ---
	"zhipu": {
		ID: "zhipu", DisplayName: "Zhipu AI (GLM)", Color: "#0066FF",
		IconClass: "zhipu", Category: "chinese",
	},
	"baidu": {
		ID: "baidu", DisplayName: "Baidu (Ernie)", Color: "#2932E1",
		IconClass: "baidu", Category: "chinese",
	},
	"alibaba": {
		ID: "alibaba", DisplayName: "Alibaba (Qwen)", Color: "#FF6A00",
		IconClass: "alibaba", Category: "chinese",
	},
	"bytedance": {
		ID: "bytedance", DisplayName: "ByteDance (Doubao)", Color: "#325AB4",
		IconClass: "bytedance", Category: "chinese",
	},
	"moonshot": {
		ID: "moonshot", DisplayName: "Moonshot (Kimi)", Color: "#6C5CE7",
		IconClass: "moonshot", Category: "chinese",
	},
	"01ai": {
		ID: "01ai", DisplayName: "01.AI (Yi)", Color: "#FF4500",
		IconClass: "01ai", Category: "chinese",
	},
	"minimax": {
		ID: "minimax", DisplayName: "MiniMax", Color: "#FF6B6B",
		IconClass: "minimax", Category: "chinese",
	},
	"siliconflow": {
		ID: "siliconflow", DisplayName: "SiliconFlow", Color: "#3B82F6",
		IconClass: "siliconflow", Category: "chinese",
	},
}

// GetProviderMeta returns display metadata for a canonical provider ID.
// Returns a zero-value ProviderMeta with the ID/DisplayName populated if the provider is unknown.
func GetProviderMeta(providerID string) ProviderMeta {
	if m, ok := providerMetaMap[providerID]; ok {
		return m
	}
	if providerID == "" {
		return ProviderMeta{ID: "unknown", DisplayName: "Unknown", Color: "#6B7280", IconClass: "unknown", Category: "unknown"}
	}
	return ProviderMeta{ID: providerID, DisplayName: providerID, Color: "#6B7280", IconClass: "generic", Category: "unknown"}
}

// AllProviderMeta returns metadata for all known providers.
func AllProviderMeta() []ProviderMeta {
	result := make([]ProviderMeta, 0, len(providerMetaMap))
	for _, m := range providerMetaMap {
		result = append(result, m)
	}
	return result
}
