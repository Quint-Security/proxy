package forwardproxy

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
)

// Word lists for generating memorable agent names.
// Format: {provider}:{adjective}-{color}-{animal}

var adjectives = [...]string{
	"bold", "brave", "bright", "brisk", "calm",
	"clear", "clever", "cool", "crisp", "curious",
	"daring", "deep", "eager", "fair", "fast",
	"fierce", "firm", "fleet", "fond", "free",
	"fresh", "glad", "grand", "great", "happy",
	"hardy", "hazy", "hearty", "honest", "humble",
	"keen", "kind", "lively", "loyal", "lucky",
	"merry", "mighty", "mild", "neat", "nimble",
	"noble", "odd", "open", "pale", "patient",
	"plain", "plucky", "polite", "proud", "pure",
	"quick", "quiet", "rapid", "rare", "ready",
	"rich", "robust", "rough", "round", "royal",
	"sharp", "shy", "silent", "sleek", "slim",
	"smart", "smooth", "snappy", "soft", "solid",
	"sound", "spare", "spry", "stark", "steady",
	"steep", "stern", "stiff", "still", "stout",
	"strong", "sunny", "super", "sure", "sweet",
	"swift", "tall", "tame", "thin", "tidy",
	"tight", "tough", "true", "vast", "vivid",
	"warm", "wary", "wide", "wild", "wise",
}

var colors = [...]string{
	"amber", "aqua", "azure", "beige", "black",
	"blue", "brass", "bronze", "brown", "cedar",
	"charcoal", "cherry", "cobalt", "copper", "coral",
	"cream", "crimson", "cyan", "dusk", "ebony",
	"ember", "fern", "flint", "frost", "garnet",
	"gilt", "gold", "granite", "grape", "green",
	"grey", "hazel", "honey", "indigo", "iron",
	"ivory", "jade", "jet", "khaki", "lava",
	"lemon", "lilac", "lime", "linen", "maple",
	"maroon", "mauve", "mint", "mocha", "moss",
	"navy", "ochre", "olive", "onyx", "opal",
	"orange", "orchid", "pearl", "peach", "pewter",
	"pine", "pink", "plum", "quartz", "red",
	"rose", "ruby", "rust", "sage", "sand",
	"scarlet", "shadow", "shell", "silver", "slate",
	"smoke", "snow", "steel", "stone", "storm",
	"sunset", "tan", "tawny", "teal", "terra",
	"thistle", "topaz", "umber", "velvet", "violet",
	"walnut", "wheat", "white", "wine", "zinc",
}

var animals = [...]string{
	"ant", "ape", "asp", "bat", "bear",
	"bee", "bird", "boar", "buck", "bull",
	"cat", "clam", "cod", "colt", "crab",
	"crow", "deer", "doe", "dove", "duck",
	"eagle", "eel", "elk", "emu", "ewe",
	"falcon", "fawn", "finch", "fish", "fly",
	"fox", "frog", "goat", "goose", "grouse",
	"gull", "hare", "hawk", "hen", "heron",
	"horse", "hound", "ibis", "jay", "kite",
	"lark", "lion", "llama", "lynx", "mare",
	"mink", "mole", "moose", "moth", "mouse",
	"mule", "newt", "owl", "ox", "panda",
	"pike", "pony", "pug", "quail", "ram",
	"rat", "raven", "robin", "roost", "seal",
	"shrew", "skunk", "slug", "snail", "snake",
	"snipe", "squid", "stag", "stoat", "stork",
	"swan", "tern", "toad", "trout", "viper",
	"vole", "wasp", "whale", "wolf", "wren",
	"yak", "zebra", "crane", "otter", "puma",
}

// GenerateWordName produces a deterministic word-based agent name from a seed.
// The seed is typically "IP:toolName" — same seed always produces the same name.
// Format: "{provider}:{adjective}-{color}-{animal}"
// If provider is empty, defaults to "agent".
func GenerateWordName(provider, seed string) string {
	if provider == "" {
		provider = "agent"
	}

	h := fnv.New64a()
	h.Write([]byte(seed))
	hash := h.Sum64()

	adjIdx := hash % uint64(len(adjectives))
	colIdx := (hash / uint64(len(adjectives))) % uint64(len(colors))
	aniIdx := (hash / uint64(len(adjectives)) / uint64(len(colors))) % uint64(len(animals))

	return fmt.Sprintf("%s:%s-%s-%s",
		provider,
		adjectives[adjIdx],
		colors[colIdx],
		animals[aniIdx],
	)
}

// DeriveChildName generates a child agent name from its parent.
// Format: "derived_{parentName}_{shortID}"
// The shortID is 4 hex chars derived from the parent ID and child number.
func DeriveChildName(parentName, parentID string, childNum int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", parentID, childNum)))
	shortID := fmt.Sprintf("%x", h[:2]) // 4 hex chars
	return fmt.Sprintf("derived_%s_%s", parentName, shortID)
}
