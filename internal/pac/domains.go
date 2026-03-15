package pac

// DefaultDomains is the built-in list of AI provider domains that should be
// routed through the Quint proxy. Wildcard patterns use shell glob syntax
// compatible with PAC shExpMatch().
var DefaultDomains = []string{
	"api.anthropic.com",
	"api.openai.com",
	"*.openai.azure.com",
	"bedrock-runtime.*.amazonaws.com",
	"generativelanguage.googleapis.com",
	"api.githubcopilot.com",
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
