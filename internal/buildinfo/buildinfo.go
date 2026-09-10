package buildinfo

// Set by release builds with -ldflags. Local builds need no Git metadata.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func Current() Info { return Info{Version, Commit, Date} }
