package cli

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/skill"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"
)

// The drift guard reads the skill as an agent will: it finds every clavis
// invocation the prose offers to copy and checks it against the command tree
// this binary actually builds, and it checks every hint the prose quotes
// against the constant the binary actually prints. A renamed flag or a
// reworded hint is then a failing test rather than a document that teaches an
// agent something the tool no longer does.

// entryLineLimit and referenceLineLimit bound the documents. The entry is
// loaded for every question, so it stays short; a reference is read on demand
// and may say more.
const (
	entryLineLimit     = 200
	referenceLineLimit = 250
)

// skillHints is the set of hint texts the skill is allowed to quote inside a
// code block. Every entry is a constant this package prints, so quoting one
// and then renaming it fails here.
func skillHints() []string {
	return []string{
		auth.UsernameHint,
		userRefHint, connectionRefHint, secretInputHint,
		queryInputHint, queryTimeHint, queryMatchHint, queryLimitHint, queryLabelHint,
		sqlBoundHint, queryFilterHint, maxRowsHint,
		skillForceHint, skillAgentHint, skillScopeHint, skillDirHint,
		skillProjectHint, skillOutputHint,
	}
}

// skillServiceHints is the allowlist for hints the platform's services print
// rather than the CLI. Their constants live in internal/database, which this
// package does not import, so a quoted one is listed here by hand and checked
// by eye in review. The skill content slice populates it.
var skillServiceHints = []string{
	// hintQueryWantsSQL, hintQueryWantsMetrics and hintQueryWantsLogs in
	// internal/database/query.go, quoted by the skill's entry.
	"This connection is postgresql: send sql.",
	"This connection is victoriametrics: send promql, labels, labelValues or series.",
	"This connection is victorialogs: send logsql, fieldNames, fieldValues, streams, streamFieldNames or streamFieldValues.",
}

// shellBreaks end the part of a line that belongs to clavis: everything after
// one of them is another program's arguments, not ours to check.
var shellBreaks = []string{"|", "||", "&&", ";", ">", ">>", "<", "2>"}

// skillInvocation is one command line the prose offers, with the line it was
// found on so a failure names a place a person can open.
type skillInvocation struct {
	line int
	text string
}

func TestSkillMatchesTheCommandTree(t *testing.T) {
	root := driftRoot()
	names := skill.Names()
	require.NotEmpty(t, names)
	found := 0
	for _, name := range names {
		body, err := skill.Render(name)
		require.NoError(t, err)
		document := string(body)
		found += len(clavisInvocations(document))
		for _, err := range checkSkillDocument(name, document, root, skillHints()) {
			assert.NoError(t, err)
		}
	}
	assert.Positive(t, found, "the skill offers at least one command to copy")
}

func TestSkillStaysWithinItsLineBounds(t *testing.T) {
	for _, name := range skill.Names() {
		body, err := skill.Render(name)
		require.NoError(t, err)
		lines := strings.Count(string(body), "\n")
		limit := referenceLineLimit
		if name == skill.Entry {
			limit = entryLineLimit
		}
		assert.Less(t, lines, limit, "%s is %d lines", name, lines)
	}
}

// TestSkillDriftGuardCatchesDrift feeds the checker documents that have
// drifted, so the guard itself is known to work rather than assumed to.
func TestSkillDriftGuardCatchesDrift(t *testing.T) {
	root := driftRoot()
	for name, tc := range map[string]struct{ document, token string }{
		"unknown flag in a fence":   {"```\nclavis query --connection <ref> --nonexistent\n```\n", "--nonexistent"},
		"unknown flag inline":       {"Run `clavis skill install --everywhere` first.\n", "--everywhere"},
		"value after a bool flag":   {"```sh\nclavis query --connection <ref> --labels -1h\n```\n", "--1h"},
		"unknown command":           {"```\nclavis describe --connection <ref>\n```\n", "describe"},
		"unknown subcommand":        {"```\nclavis connections describe\n```\n", "describe"},
		"flag of another command":   {"```\nclavis skill install --promql up\n```\n", "--promql"},
		"flag with an inline value": {"```\nclavis query --connection=<ref> --sqlx=1\n```\n", "--sqlx"},
		"unterminated quote":        {"```\nclavis query --sql \"select 1\n```\n", "clavis query"},
		"unquoted hint":             {"```\nHint: use --force sometimes\n```\n", "Hint: use --force sometimes"},
	} {
		t.Run(name, func(t *testing.T) {
			found := checkSkillDocument("victorialogs.md", tc.document, root, skillHints())
			require.Len(t, found, 1, "%v", found)
			assert.Contains(t, found[0].Error(), "victorialogs.md")
			assert.Contains(t, found[0].Error(), tc.token)
		})
	}
	// The same documents with the drift repaired report nothing.
	for _, document := range []string{
		"```\nclavis query --connection <ref> --sql \"select 1\"\n```\n",
		"```\nclavis query --connection <ref> --logsql 'error' --start -1h --end -15m --limit 5\n```\n",
		"Run `clavis skill install --force` first.\n",
		"```\nclavis connections list --selector team=data | jq --raw-output .\n```\n",
		"```\n$ clavis query --connection <ref> --logsql '*' \\\n    --limit 10\n```\n",
		"```\nclavis query --connection <ref> --sql-stdin <<'SQL'\nselect --not-a-flag\nSQL\n```\n",
		"```\nHint: " + skillForceHint + "\n```\n",
		"Prose naming --nonexistent outside a fence and outside backticks.\n",
	} {
		assert.Empty(t, checkSkillDocument("SKILL.md", document, driftRoot(), skillHints()), document)
	}
}

// driftRoot builds the tree the binary runs, with callbacks that do nothing:
// the guard reads names and flags, never actions.
func driftRoot() *urfave.Command {
	return newRootCommand(IO{}.withDefaults(), io.Discard, errors.New("invalid"),
		func(*urfave.Command) error { return nil }, func(Result) {})
}

// checkSkillDocument returns one error per finding, so the guard can be tested
// on a planted document without failing the suite that tests it.
func checkSkillDocument(name, document string, root *urfave.Command, hints []string) []error {
	var found []error
	for _, invocation := range clavisInvocations(document) {
		if err := checkInvocation(root, invocation.text); err != nil {
			found = append(found, fmt.Errorf("%s:%d: %w", name, invocation.line, err))
		}
	}
	for _, quoted := range quotedHints(document) {
		if slices.Contains(hints, quoted.text) || slices.Contains(skillServiceHints, quoted.text) {
			continue
		}
		found = append(found, fmt.Errorf("%s:%d: quotes a hint no constant prints: Hint: %s",
			name, quoted.line, quoted.text))
	}
	return found
}

// clavisInvocations finds the command lines a reader can copy: a line of a
// fenced block, and the text of an inline backtick span. A fenced line
// continued with a trailing backslash is joined with the one after it, because
// that is one command however it is wrapped.
func clavisInvocations(document string) []skillInvocation {
	var found []skillInvocation
	lines := strings.Split(document, "\n")
	fenced := false
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if !fenced {
			found = append(found, inlineInvocations(index+1, line)...)
			continue
		}
		text := strings.TrimPrefix(strings.TrimSpace(line), "$ ")
		start := index
		for strings.HasSuffix(text, "\\") && index+1 < len(lines) {
			index++
			text = strings.TrimSuffix(text, "\\") + " " + strings.TrimSpace(lines[index])
		}
		if isInvocation(text) {
			found = append(found, skillInvocation{line: start + 1, text: text})
		}
	}
	return found
}

// inlineInvocations reads the backtick spans of one prose line. Prose that
// merely mentions a flag is not an invocation: only a span that starts with
// the command itself is one.
func inlineInvocations(line int, text string) []skillInvocation {
	var found []skillInvocation
	parts := strings.Split(text, "`")
	// Every second part is inside a span; an unmatched final backtick leaves a
	// trailing part that is prose again.
	for index := 1; index < len(parts)-1; index += 2 {
		if isInvocation(parts[index]) {
			found = append(found, skillInvocation{line: line, text: parts[index]})
		}
	}
	return found
}

func isInvocation(text string) bool {
	trimmed := strings.TrimSpace(text)
	return trimmed == "clavis" || strings.HasPrefix(trimmed, "clavis ")
}

// quotedHints finds the hint lines the prose shows inside a fenced block,
// which is where a transcript of a refusal is quoted.
func quotedHints(document string) []skillInvocation {
	var found []skillInvocation
	fenced := false
	for index, line := range strings.Split(document, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if text, ok := strings.CutPrefix(strings.TrimSpace(line), "Hint: "); fenced && ok {
			found = append(found, skillInvocation{line: index + 1, text: text})
		}
	}
	return found
}

// checkInvocation walks the command path the invocation names and then checks
// every flag it passes against that command and the root. A value is not
// checked: the source's own query language is not this binary's business, and
// a placeholder such as <ref> stands for whatever the reader will type.
func checkInvocation(root *urfave.Command, text string) error {
	tokens, ok := tokenize(text)
	if !ok {
		return fmt.Errorf("could not read the invocation as a command line: %s", text)
	}
	command := root
	index := 1
	for ; index < len(tokens); index++ {
		token := tokens[index]
		if endsCommand(token) {
			return nil
		}
		if strings.HasPrefix(token, "-") || placeholder(token) {
			break
		}
		next := subcommand(command, token)
		if next == nil {
			// help is urfave's own, on every command, and never declared.
			if token == "help" {
				return nil
			}
			// No command takes a positional argument, so a word here is a
			// command name and nothing else it could be.
			return fmt.Errorf("names a command %s does not have: %s", commandPath(root, command), token)
		}
		command = next
	}
	for ; index < len(tokens); index++ {
		token := tokens[index]
		if endsCommand(token) {
			return nil
		}
		if !strings.HasPrefix(token, "-") || token == "-" || token == "--" {
			continue
		}
		name, _, attached := strings.Cut(strings.TrimLeft(token, "-"), "=")
		if name == "help" {
			continue
		}
		flag := flagOf(command, name)
		if flag == nil {
			flag = flagOf(root, name)
		}
		if flag == nil {
			return fmt.Errorf("names a flag %s does not take: --%s", commandPath(root, command), name)
		}
		// A flag that takes a value owns the next token, whatever it looks
		// like: a relative time such as -1h is a value, not a flag.
		if !attached && !isBoolFlag(flag) {
			index++
		}
	}
	return nil
}

// flagOf finds a declared flag by any of its names.
func flagOf(command *urfave.Command, name string) urfave.Flag {
	for _, flag := range command.Flags {
		if slices.Contains(flag.Names(), name) {
			return flag
		}
	}
	return nil
}

// isBoolFlag reports whether a flag stands alone on the command line.
func isBoolFlag(flag urfave.Flag) bool {
	_, ok := flag.(*urfave.BoolFlag)
	return ok
}

// endsCommand names the tokens after which the line stops being ours: a pipe,
// a redirection, a separator or a comment. What follows belongs to another
// program or to the reader.
func endsCommand(token string) bool {
	return slices.Contains(shellBreaks, token) || strings.HasPrefix(token, "#")
}

// placeholder is a stand-in the prose writes for a value the reader supplies,
// such as <ref>. It ends the command path rather than naming a command.
func placeholder(token string) bool {
	return strings.HasPrefix(token, "<") && strings.HasSuffix(token, ">")
}

func subcommand(command *urfave.Command, name string) *urfave.Command {
	for _, child := range command.Commands {
		if child.Name == name || slices.Contains(child.Aliases, name) {
			return child
		}
	}
	return nil
}

// commandPath names the command a failure is about the way a reader typed it.
func commandPath(root, command *urfave.Command) string {
	if command == root {
		return "clavis"
	}
	for _, child := range root.Commands {
		if child == command {
			return "clavis " + child.Name
		}
		for _, grandchild := range child.Commands {
			if grandchild == command {
				return "clavis " + child.Name + " " + grandchild.Name
			}
		}
	}
	return "clavis " + command.Name
}

// tokenize splits a command line the way a shell would, honoring single
// quotes, double quotes and backslash escapes. An unterminated quote is not a
// command line anyone can run, and is reported rather than guessed at.
func tokenize(text string) ([]string, bool) {
	var tokens []string
	var token strings.Builder
	chars := []rune(text)
	open := false
	var quote rune
	for index := 0; index < len(chars); index++ {
		char := chars[index]
		switch {
		case quote == '\'':
			if char == '\'' {
				quote = 0
				continue
			}
		case quote == '"':
			if char == '\\' && index+1 < len(chars) {
				index++
				token.WriteRune(chars[index])
				continue
			}
			if char == '"' {
				quote = 0
				continue
			}
		case char == '\'' || char == '"':
			quote, open = char, true
			continue
		case char == '#' && !open:
			// An unquoted comment ends the command line; what follows is
			// prose and may hold an apostrophe.
			index = len(chars)
			continue
		case char == '\\' && index+1 < len(chars):
			index++
			token.WriteRune(chars[index])
			open = true
			continue
		case char == ' ' || char == '\t':
			if open {
				tokens = append(tokens, token.String())
				token.Reset()
				open = false
			}
			continue
		}
		token.WriteRune(char)
		open = true
	}
	if quote != 0 {
		return nil, false
	}
	if open {
		tokens = append(tokens, token.String())
	}
	return tokens, true
}
