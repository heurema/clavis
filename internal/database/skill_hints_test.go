package database

import (
	"testing"

	"github.com/heurema/clavis/internal/skill"
	"github.com/stretchr/testify/require"
)

// The skill quotes the service's provider-mismatch hints verbatim, and the CLI
// package cannot import the constants, so the check that the two stay equal
// lives beside the constants: a reworded hint fails here until the skill
// follows.
func TestSkillQuotesTheProviderHintsVerbatim(t *testing.T) {
	entry, err := skill.Render(skill.Entry)
	require.NoError(t, err)
	require.Contains(t, string(entry), hintQueryWantsLogs)
}
