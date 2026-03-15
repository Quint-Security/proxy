package pac

// DefaultDomains is the list of domains routed through the Quint proxy via PAC.
//
// IMPORTANT: AI provider API domains (Anthropic, OpenAI, Bedrock, etc.) are NOT
// in this list. They are routed via per-agent shell wrappers (env.sh) which
// health-check the proxy before routing. This prevents the proxy from breaking
// AI agent connectivity if it's down or unhealthy.
//
// The PAC file only routes tool/MCP API domains that GUI apps (Cursor, Windsurf)
// call directly. These are smaller requests where MITM is reliable.
var DefaultDomains = []string{
	// GitHub API — tool calls from agents
	"api.github.com",
	"*.githubcopilot.com",
	// Common MCP server backends
	"api.slack.com",
	"api.notion.com",
	"api.linear.app",
	"api.atlassian.com",
	"*.atlassian.net",
}

// LLMProviderDomains are AI provider API domains routed only via CLI wrappers
// (env.sh / env.fish), NOT via the PAC file. The wrappers health-check the proxy
// before routing, so a broken proxy never disrupts AI agent connectivity.
var LLMProviderDomains = []string{
	"api.anthropic.com",
	"api.openai.com",
	"*.openai.azure.com",
	"bedrock-runtime.*.amazonaws.com",
	"generativelanguage.googleapis.com",
	"api.codeium.com",
	"api-inference.huggingface.co",
	"api.fireworks.ai",
	"api.together.xyz",
	"api.groq.com",
	"api.mistral.ai",
	"api.deepseek.com",
	"api.cohere.com",
	"api.x.ai",
}
