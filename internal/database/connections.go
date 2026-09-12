package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/provider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// connectionMutationLock serializes every connection mutation and every check
// across instances, so a name cannot be taken twice and a probe cannot race a
// credential replacement. It is distinct from MigrationLock, limitLock and
// adminMutationLock; listing and get never take it.
const connectionMutationLock int64 = 0x434c415649530004

var _ auth.Connections = (*LocalAuth)(nil)

// Hints are fixed application text: they name the next action or the valid
// range and never echo a submitted value, which could carry a secret or a host.
const (
	hintConnectionNotFound = "Use `clavis connections list` to find the connection's name or id."
	hintConnectionExists   = "A connection named like that exists; use `clavis connections update` to change it or choose another name."
	hintConnectionInUse    = "Disable the connection first; no grants remain."
	hintUserNotFound       = "Use `clavis users list` to find the user's username or id."
	hintCredentials        = "Replace the connection's credentials with `clavis connections set-credentials`; the stored secret cannot be decrypted with the configured key."
	hintName               = "A connection name is 3 to 64 characters of lowercase letters, digits, dot, dash or underscore, starts with a letter and is never shaped like a UUID."
	hintTitle              = "A title is 1 to 128 characters without control characters."
	hintText               = "Description and scope are at most 2000 characters without control characters."
	hintLabels             = "At most 16 labels; keys and values are 1 to 63 characters of lowercase letters, digits, dot, dash or underscore."
	hintTimeout            = "The statement timeout is 1000 to 120000 milliseconds; 0 selects the default of 30000."
	hintRows               = "The row cap is 1 to 100000 rows; 0 selects the default of 1000."
	hintBytes              = "The byte cap is 1024 to 10485760 bytes; 0 selects the default of 1048576."
	hintSelector           = "A selector has at most 8 comma-separated terms of the form key=value, key!=value or key."
)

// noSecret stands in for an authentication method that takes no secret: the
// column and the keyring both refuse an empty envelope, and a stored secret
// can never be this value because null bytes are rejected at validation.
var noSecret = []byte{0}

func invalidArgument(hint string) error { return &auth.Error{Code: auth.InvalidArgument, Hint: hint} }

// hintConnectionGrants states how many grants still block a delete, so the
// caller knows exactly how much revoking is left before retrying.
func hintConnectionGrants(count int64) string {
	if count == 1 {
		return "1 grant remains; revoke it with `clavis grants revoke` first."
	}
	return fmt.Sprintf("%d grants remain; revoke them with `clavis grants revoke` first.", count)
}

// hintConnectionGuard names every condition that blocks a delete at once, so
// one dry run tells the caller the whole path: disable, then revoke the
// counted grants.
func hintConnectionGuard(enabled bool, grants int64) string {
	switch {
	case enabled && grants == 1:
		return "Disable the connection first; 1 grant also remains, revoke it with `clavis grants revoke`."
	case enabled && grants > 1:
		return fmt.Sprintf("Disable the connection first; %d grants also remain, revoke them with `clavis grants revoke`.", grants)
	case enabled:
		return hintConnectionInUse
	default:
		return hintConnectionGrants(grants)
	}
}

func connectionNotFound() error {
	return &auth.Error{Code: auth.ConnectionNotFound, Hint: hintConnectionNotFound}
}

func connectionExists() error {
	return &auth.Error{Code: auth.ConnectionExists, Hint: hintConnectionExists}
}

func connectionContext(id string) string { return "connection:" + id }

// hinted restores the guidance a committed denial drops: the recorded event
// carries the code alone, so the error the deny path returns is rebuilt from
// it. The text is fixed per code and never echoes input.
func hinted(err error) error {
	var failure *auth.Error
	if !errors.As(err, &failure) || failure.Hint != "" {
		return err
	}
	switch failure.Code {
	case auth.ConnectionExists:
		failure.Hint = hintConnectionExists
	case auth.ConnectionNotFound:
		failure.Hint = hintConnectionNotFound
	case auth.ConnectionInUse:
		failure.Hint = hintConnectionInUse
	case auth.CredentialsUnavailable:
		failure.Hint = hintCredentials
	case auth.UserNotFound:
		failure.Hint = hintUserNotFound
	}
	return err
}

// seal encrypts one secret for the connection it belongs to. It runs outside
// the transaction where the identifier is known in advance; unlike password
// hashing it costs microseconds, so a replacement may seal under the row lock.
func (s *LocalAuth) seal(secret auth.Secret, id string) (string, error) {
	if s.keys == nil {
		return "", unavailable()
	}
	plaintext := []byte(secret)
	if len(plaintext) == 0 {
		plaintext = noSecret
	}
	envelope, err := s.keys.Seal(plaintext, connectionContext(id))
	if err != nil {
		return "", unavailable()
	}
	return envelope, nil
}

// open returns the stored plaintext, or false for every reason an envelope
// cannot be opened: a missing keyring, a different key, a tampered or moved
// envelope. Callers must not distinguish them.
func (s *LocalAuth) open(envelope, id string) ([]byte, bool) {
	if s.keys == nil {
		return nil, false
	}
	plaintext, err := s.keys.Open(envelope, connectionContext(id))
	if err != nil {
		return nil, false
	}
	if bytes.Equal(plaintext, noSecret) {
		return []byte{}, true
	}
	return plaintext, true
}

// validText bounds one free-text field in runes, the way the column's
// constraint counts them, and refuses control characters and invalid UTF-8,
// which no display surface should have to escape.
func validText(value string, maximum int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// connectionBound applies one resource bound: zero selects the documented
// default, any other value must sit inside the ceilings the schema enforces.
func connectionBound(value, fallback, low, high int, hint string) (int32, error) {
	if value == 0 {
		value = fallback
	}
	if value < low || value > high {
		return 0, invalidArgument(hint)
	}
	return int32(value), nil
}

func statementTimeoutBound(value int) (int32, error) {
	return connectionBound(value, int(auth.DefaultStatementTimeout/time.Millisecond),
		int(auth.MinStatementTimeout/time.Millisecond), int(auth.MaxStatementTimeout/time.Millisecond), hintTimeout)
}

func maxRowsBound(value int) (int32, error) {
	return connectionBound(value, auth.DefaultMaxRows, 1, auth.MaxMaxRows, hintRows)
}

func maxBytesBound(value int) (int32, error) {
	return connectionBound(value, auth.DefaultMaxBytes, auth.MinMaxBytes, auth.MaxMaxBytes, hintBytes)
}

// encodeStrings keeps a nil map out of the column: the schema requires a JSON
// object, and "null" is not one.
func encodeStrings(values map[string]string) ([]byte, error) {
	if values == nil {
		values = map[string]string{}
	}
	return json.Marshal(values)
}

func decodeStrings(raw []byte) (map[string]string, error) {
	values := map[string]string{}
	if len(raw) == 0 {
		return values, nil
	}
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	return values, nil
}

// connectionRecord is the safe administrative projection of a row. The secret
// envelope has no field to travel in.
func connectionRecord(row sqlc.Connection) (auth.Connection, error) {
	target, err := decodeStrings(row.Target)
	if err != nil {
		return auth.Connection{}, err
	}
	labels, err := decodeStrings(row.Labels)
	if err != nil {
		return auth.Connection{}, err
	}
	record := auth.Connection{
		ID: row.ID, Name: row.Name, Title: row.Title, Description: row.Description, Scope: row.Scope,
		Provider: auth.ProviderType(row.Provider), Target: target, Labels: labels, Enabled: row.Enabled,
		StatementTimeoutMS: int(row.StatementTimeoutMs), MaxRows: int(row.MaxRows), MaxBytes: int(row.MaxBytes),
		CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC(),
	}
	if row.LastCheckOutcome != nil && row.LastCheckAt != nil {
		record.LastCheck = &auth.CheckResult{
			Outcome: auth.CheckOutcome(*row.LastCheckOutcome), CheckedAt: row.LastCheckAt.UTC(),
		}
	}
	return record, nil
}

// connectionProvider recovers the provider and the stored target of a row. A
// row this build cannot interpret is a broken invariant, not a caller error,
// so it reports unavailability rather than blaming the request.
func connectionProvider(row sqlc.Connection) (provider.Provider, map[string]string, error) {
	implementation, ok := provider.Lookup(auth.ProviderType(row.Provider))
	if !ok {
		return nil, nil, unavailable()
	}
	target, err := decodeStrings(row.Target)
	if err != nil {
		return nil, nil, unavailable()
	}
	return implementation, target, nil
}

// findConnection resolves a UUID or a name. A valid name can never parse as a
// UUID, so UUID syntax decides which lookup runs and the fallback is
// unambiguous. Mutations lock the row; reads do not.
func findConnection(ctx context.Context, queries *sqlc.Queries, ref string, lock bool) (sqlc.Connection, error) {
	var row sqlc.Connection
	if !auth.ValidConnectionRef(ref) {
		return row, connectionNotFound()
	}
	id := ref
	if !auth.ValidUserID(ref) {
		named, err := queries.FindConnectionByName(ctx, ref)
		if errors.Is(err, pgx.ErrNoRows) {
			return row, connectionNotFound()
		}
		if err != nil {
			return row, err
		}
		if !lock {
			return named, nil
		}
		id = named.ID
	}
	var err error
	if lock {
		row, err = queries.LockConnection(ctx, id)
	} else {
		row, err = queries.FindConnectionByID(ctx, id)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return row, connectionNotFound()
	}
	return row, err
}

func lockConnection(ctx context.Context, queries *sqlc.Queries, ref string) (sqlc.Connection, error) {
	return findConnection(ctx, queries, ref, true)
}

// nameGuarded runs one statement that can still lose the unique index race to
// a row committed outside the advisory lock, inside a savepoint that keeps the
// transaction usable for the deny event.
func nameGuarded(ctx context.Context, tx pgx.Tx, run func(*sqlc.Queries) (sqlc.Connection, error)) (sqlc.Connection, error) {
	var row sqlc.Connection
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return row, err
	}
	row, err = run(sqlc.New(savepoint))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if err := savepoint.Rollback(ctx); err != nil {
			return row, err
		}
		return row, connectionExists()
	}
	if err != nil {
		return row, err
	}
	if err := savepoint.Commit(ctx); err != nil {
		return row, err
	}
	return row, nil
}

// connectionInsert validates the whole request before any I/O and returns the
// row to write. Provider-specific parsing produces its own hints.
func connectionInsert(request auth.CreateConnectionRequest) (sqlc.InsertConnectionParams, error) {
	var params sqlc.InsertConnectionParams
	if !auth.ValidConnectionName(request.Name) {
		return params, invalidArgument(hintName)
	}
	// An omitted title is the name: a caller that never passes one still
	// satisfies the column's 1 to 128 character constraint.
	if request.Title == "" {
		request.Title = request.Name
	}
	if !validText(request.Title, auth.MaxTitleLength) {
		return params, invalidArgument(hintTitle)
	}
	if !validText(request.Description, auth.MaxDescriptionLength) || !validText(request.Scope, auth.MaxDescriptionLength) {
		return params, invalidArgument(hintText)
	}
	implementation, ok := provider.Lookup(request.Provider)
	if !ok {
		return params, invalidArgument(provider.TypeHint())
	}
	if !auth.ValidLabels(request.Labels) {
		return params, invalidArgument(hintLabels)
	}
	timeout, err := statementTimeoutBound(request.StatementTimeoutMS)
	if err != nil {
		return params, err
	}
	rows, err := maxRowsBound(request.MaxRows)
	if err != nil {
		return params, err
	}
	size, err := maxBytesBound(request.MaxBytes)
	if err != nil {
		return params, err
	}
	target, err := implementation.ParseTarget(request.Target)
	if err != nil {
		return params, err
	}
	if err := implementation.ValidateSecret(target, request.Secret); err != nil {
		return params, err
	}
	encodedTarget, err := encodeStrings(target)
	if err != nil {
		return params, unavailable()
	}
	encodedLabels, err := encodeStrings(request.Labels)
	if err != nil {
		return params, unavailable()
	}
	return sqlc.InsertConnectionParams{
		Name: request.Name, Title: request.Title, Description: request.Description, Scope: request.Scope,
		Provider: string(request.Provider), Target: encodedTarget, Labels: encodedLabels,
		StatementTimeoutMs: timeout, MaxRows: rows, MaxBytes: size,
	}, nil
}

// connectionUpdate validates every supplied field and reports whether the
// title is being reset to the connection's name. The target needs the row's
// provider, so it is parsed inside the transaction instead.
func connectionUpdate(request auth.UpdateConnectionRequest) (sqlc.UpdateConnectionParams, bool, error) {
	var params sqlc.UpdateConnectionParams
	if request.Name != nil {
		if !auth.ValidConnectionName(*request.Name) {
			return params, false, invalidArgument(hintName)
		}
		params.Name = request.Name
	}
	// An explicitly emptied title returns to the name rather than failing the
	// column's constraint; that name is known only inside the transaction.
	resetTitle := request.Title != nil && *request.Title == ""
	if request.Title != nil && !resetTitle {
		if !validText(*request.Title, auth.MaxTitleLength) {
			return params, false, invalidArgument(hintTitle)
		}
		params.Title = request.Title
	}
	for _, value := range []*string{request.Description, request.Scope} {
		if value != nil && !validText(*value, auth.MaxDescriptionLength) {
			return params, false, invalidArgument(hintText)
		}
	}
	params.Description, params.Scope = request.Description, request.Scope
	if request.Labels != nil {
		if !auth.ValidLabels(*request.Labels) {
			return params, false, invalidArgument(hintLabels)
		}
		encoded, err := encodeStrings(*request.Labels)
		if err != nil {
			return params, false, unavailable()
		}
		params.Labels = encoded
	}
	for _, bound := range []struct {
		value  *int
		parse  func(int) (int32, error)
		target **int32
	}{
		{request.StatementTimeoutMS, statementTimeoutBound, &params.StatementTimeoutMs},
		{request.MaxRows, maxRowsBound, &params.MaxRows},
		{request.MaxBytes, maxBytesBound, &params.MaxBytes},
	} {
		if bound.value == nil {
			continue
		}
		parsed, err := bound.parse(*bound.value)
		if err != nil {
			return params, false, err
		}
		*bound.target = &parsed
	}
	return params, resetTitle, nil
}

func (s *LocalAuth) CreateConnection(ctx context.Context, session auth.Session,
	request auth.CreateConnectionRequest, dryRun bool) (auth.ConnectionMutation, error) {
	var result auth.ConnectionMutation
	params, err := connectionInsert(request)
	if err != nil {
		return result, err
	}
	// The envelope is bound to the identifier, so the identifier is generated
	// and the secret sealed before the transaction opens.
	id, err := bootstrapID()
	if err != nil {
		return result, unavailable()
	}
	params.ID = id
	if params.SecretEnvelope, err = s.seal(request.Secret, id); err != nil {
		return result, err
	}
	err = s.administer(ctx, session, connectionMutationLock, "", string(auth.EventConnectionCreate), dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) (mutation, error) {
			queries := sqlc.New(tx)
			exists, err := queries.ConnectionNameExists(ctx, params.Name)
			if err != nil {
				return mutation{}, err
			}
			if exists {
				return mutation{}, connectionExists()
			}
			row, err := nameGuarded(ctx, tx, func(q *sqlc.Queries) (sqlc.Connection, error) {
				return q.InsertConnection(ctx, params)
			})
			if err != nil {
				return mutation{}, err
			}
			record, err := connectionRecord(row)
			if err != nil {
				return mutation{}, err
			}
			result = auth.ConnectionMutation{Connection: record, DryRun: dryRun}
			return mutation{target: row.ID}, nil
		})
	if err != nil {
		return auth.ConnectionMutation{}, hinted(err)
	}
	return result, nil
}

func (s *LocalAuth) UpdateConnection(ctx context.Context, session auth.Session, ref string,
	request auth.UpdateConnectionRequest, dryRun bool) (auth.ConnectionMutation, error) {
	var result auth.ConnectionMutation
	params, resetTitle, err := connectionUpdate(request)
	if err != nil {
		return result, err
	}
	err = s.administer(ctx, session, connectionMutationLock, "", string(auth.EventConnectionUpdate), dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) (mutation, error) {
			queries := sqlc.New(tx)
			row, err := lockConnection(ctx, queries, ref)
			if err != nil {
				return mutation{}, err
			}
			params.ID = row.ID
			if resetTitle {
				title := row.Name
				if params.Name != nil {
					title = *params.Name
				}
				params.Title = &title
			}
			if params.Name != nil && *params.Name != row.Name {
				exists, err := queries.ConnectionNameExists(ctx, *params.Name)
				if err != nil {
					return mutation{}, err
				}
				if exists {
					return mutation{target: row.ID}, connectionExists()
				}
			}
			if request.Target != nil {
				implementation, _, err := connectionProvider(row)
				if err != nil {
					return mutation{}, err
				}
				target, err := implementation.ParseTarget(*request.Target)
				if err != nil {
					return mutation{target: row.ID}, err
				}
				if params.Target, err = encodeStrings(target); err != nil {
					return mutation{}, err
				}
			}
			updated, err := nameGuarded(ctx, tx, func(q *sqlc.Queries) (sqlc.Connection, error) {
				return q.UpdateConnection(ctx, params)
			})
			if err != nil {
				return mutation{target: row.ID}, err
			}
			record, err := connectionRecord(updated)
			if err != nil {
				return mutation{}, err
			}
			result = auth.ConnectionMutation{Connection: record, DryRun: dryRun}
			return mutation{target: row.ID}, nil
		})
	if err != nil {
		return auth.ConnectionMutation{}, hinted(err)
	}
	return result, nil
}

func (s *LocalAuth) SetConnectionCredentials(ctx context.Context, session auth.Session, ref string,
	secret auth.Secret, dryRun bool) (auth.ConnectionMutation, error) {
	var result auth.ConnectionMutation
	if s.keys == nil {
		return result, unavailable()
	}
	err := s.administer(ctx, session, connectionMutationLock, "", string(auth.EventConnectionSecrets), dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) (mutation, error) {
			queries := sqlc.New(tx)
			row, err := lockConnection(ctx, queries, ref)
			if err != nil {
				return mutation{}, err
			}
			implementation, target, err := connectionProvider(row)
			if err != nil {
				return mutation{}, err
			}
			if err := implementation.ValidateSecret(target, secret); err != nil {
				return mutation{target: row.ID}, err
			}
			envelope, err := s.seal(secret, row.ID)
			if err != nil {
				return mutation{}, err
			}
			updated, err := queries.SetConnectionSecret(ctx, sqlc.SetConnectionSecretParams{
				SecretEnvelope: envelope, ID: row.ID,
			})
			if err != nil {
				return mutation{}, err
			}
			record, err := connectionRecord(updated)
			if err != nil {
				return mutation{}, err
			}
			result = auth.ConnectionMutation{Connection: record, DryRun: dryRun}
			return mutation{target: row.ID}, nil
		})
	if err != nil {
		return auth.ConnectionMutation{}, hinted(err)
	}
	return result, nil
}

// SetConnectionEnabled is idempotent: setting the state a connection already
// has succeeds and is audited like any other attempt.
func (s *LocalAuth) SetConnectionEnabled(ctx context.Context, session auth.Session, ref string,
	enabled, dryRun bool) (auth.ConnectionMutation, error) {
	var result auth.ConnectionMutation
	action := auth.EventConnectionDisable
	if enabled {
		action = auth.EventConnectionEnable
	}
	err := s.administer(ctx, session, connectionMutationLock, "", string(action), dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) (mutation, error) {
			queries := sqlc.New(tx)
			row, err := lockConnection(ctx, queries, ref)
			if err != nil {
				return mutation{}, err
			}
			updated, err := queries.SetConnectionEnabled(ctx, sqlc.SetConnectionEnabledParams{
				Enabled: enabled, ID: row.ID,
			})
			if err != nil {
				return mutation{}, err
			}
			record, err := connectionRecord(updated)
			if err != nil {
				return mutation{}, err
			}
			result = auth.ConnectionMutation{Connection: record, DryRun: dryRun}
			return mutation{target: row.ID}, nil
		})
	if err != nil {
		return auth.ConnectionMutation{}, hinted(err)
	}
	return result, nil
}

func (s *LocalAuth) DeleteConnection(ctx context.Context, session auth.Session, ref string,
	dryRun bool) (auth.ConnectionDeletion, error) {
	var result auth.ConnectionDeletion
	// The committed denial carries the code alone, so the counted hint is kept
	// here and re-attached to the error the deny path returns.
	var guard string
	err := s.administer(ctx, session, connectionMutationLock, "", string(auth.EventConnectionDelete), dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) (mutation, error) {
			queries := sqlc.New(tx)
			row, err := lockConnection(ctx, queries, ref)
			if err != nil {
				return mutation{}, err
			}
			// The identifier is verified here, so the guard's denial event
			// can name it. Both guards are evaluated together so the hint
			// tells the caller everything that still stands in the way.
			grants, err := queries.CountConnectionGrants(ctx, row.ID)
			if err != nil {
				return mutation{}, err
			}
			if row.Enabled || grants > 0 {
				guard = hintConnectionGuard(row.Enabled, grants)
				return mutation{target: row.ID}, &auth.Error{Code: auth.ConnectionInUse, Hint: guard}
			}
			removed, err := queries.DeleteConnection(ctx, row.ID)
			if err != nil {
				return mutation{}, err
			}
			if removed != 1 {
				return mutation{}, unavailable()
			}
			result = auth.ConnectionDeletion{ID: row.ID, Name: row.Name, Deleted: true, DryRun: dryRun}
			return mutation{target: row.ID}, nil
		})
	if err != nil {
		var failure *auth.Error
		if guard != "" && errors.As(err, &failure) && failure.Code == auth.ConnectionInUse {
			failure.Hint = guard
		}
		return auth.ConnectionDeletion{}, hinted(err)
	}
	return result, nil
}

// probe opens the stored envelope, runs the provider's probe and wipes the
// plaintext buffer as soon as the probe returns.
func (s *LocalAuth) probe(ctx context.Context, implementation provider.Provider,
	row sqlc.Connection, target map[string]string) (auth.CheckOutcome, bool) {
	plaintext, ok := s.open(row.SecretEnvelope, row.ID)
	if !ok {
		return "", false
	}
	defer func() {
		for index := range plaintext {
			plaintext[index] = 0
		}
	}()
	return implementation.Probe(ctx, target, auth.Secret(plaintext)), true
}

// CheckConnection contacts the source on request only. The stored outcome is
// a safe category; no driver text reaches the result, the event or a log.
func (s *LocalAuth) CheckConnection(ctx context.Context, session auth.Session, ref string) (auth.ConnectionCheck, error) {
	var result auth.ConnectionCheck
	err := s.administer(ctx, session, connectionMutationLock, "", string(auth.EventConnectionCheck), false, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) (mutation, error) {
			queries := sqlc.New(tx)
			row, err := lockConnection(ctx, queries, ref)
			if err != nil {
				return mutation{}, err
			}
			implementation, target, err := connectionProvider(row)
			if err != nil {
				return mutation{}, err
			}
			outcome, opened := s.probe(ctx, implementation, row, target)
			if !opened {
				outcome = auth.CheckCredentialsUnavailable
			}
			updated, err := queries.SetConnectionCheck(ctx, sqlc.SetConnectionCheckParams{
				Outcome: string(outcome), ID: row.ID,
			})
			if err != nil {
				return mutation{}, err
			}
			// The denial commits the stored outcome together with its event.
			if !opened {
				return mutation{target: row.ID}, &auth.Error{Code: auth.CredentialsUnavailable, Hint: hintCredentials}
			}
			record, err := connectionRecord(updated)
			if err != nil || record.LastCheck == nil {
				return mutation{}, unavailable()
			}
			result = auth.ConnectionCheck{Connection: record, Check: *record.LastCheck}
			if outcome != auth.CheckReachable {
				return mutation{target: row.ID, outcome: "check_failed"}, nil
			}
			return mutation{target: row.ID}, nil
		})
	if err != nil {
		return auth.ConnectionCheck{}, hinted(err)
	}
	return result, nil
}

// compileSelector turns parsed terms into the query's three inputs:
// containment for equality, an array of single-key objects for inequality and
// a key list for existence. Two equality terms on one key with different
// values can never both hold, which the caller answers with an empty listing.
func compileSelector(terms []auth.SelectorTerm) (sqlc.ListConnectionsParams, bool, error) {
	var params sqlc.ListConnectionsParams
	if len(terms) > auth.MaxSelectorTerms {
		return params, false, invalidArgument(hintSelector)
	}
	contains := map[string]string{}
	excludes := make([]map[string]string, 0, len(terms))
	keys := make([]string, 0, len(terms))
	for _, term := range terms {
		if !auth.ValidLabelKey(term.Key) ||
			(term.Op != auth.SelectorExists && !auth.ValidLabelValue(term.Value)) {
			return params, false, invalidArgument(hintSelector)
		}
		switch term.Op {
		case auth.SelectorEquals:
			if previous, repeated := contains[term.Key]; repeated && previous != term.Value {
				return params, false, nil
			}
			contains[term.Key] = term.Value
		case auth.SelectorNotEquals:
			excludes = append(excludes, map[string]string{term.Key: term.Value})
		case auth.SelectorExists:
			keys = append(keys, term.Key)
		default:
			return params, false, invalidArgument(hintSelector)
		}
	}
	encodedContains, err := json.Marshal(contains)
	if err != nil {
		return params, false, unavailable()
	}
	encodedExcludes, err := json.Marshal(excludes)
	if err != nil {
		return params, false, unavailable()
	}
	params.Contains, params.Excludes, params.Keys = encodedContains, encodedExcludes, keys
	return params, true, nil
}

// ListConnections is a read: it takes no advisory key and records no event on
// success. A denied attempt is recorded as connections.list.
func (s *LocalAuth) ListConnections(ctx context.Context, previous auth.Session,
	terms []auth.SelectorTerm, limit int) (auth.ConnectionList, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var list auth.ConnectionList
	list.Connections = []auth.Connection{}
	if !validSession(previous) {
		return list, &auth.Error{Code: auth.Unauthenticated}
	}
	params, satisfiable, err := compileSelector(terms)
	if err != nil {
		return list, err
	}
	if limit <= 0 || limit > auth.MaxConnectionListing {
		limit = auth.MaxConnectionListing
	}
	params.LimitRows = int32(limit) + 1
	if err := s.ready(ctx); err != nil {
		return list, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return list, unavailable()
	}
	defer rollback(ctx, tx)
	if _, err := authorize(ctx, tx, previous, string(auth.EventConnectionsList)); err != nil {
		return list, err
	}
	var rows []sqlc.Connection
	if satisfiable {
		if rows, err = sqlc.New(tx).ListConnections(ctx, params); err != nil {
			return list, unavailable()
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return list, unavailable()
	}
	for index, row := range rows {
		if index == limit {
			list.Truncated = true
			break
		}
		record, err := connectionRecord(row)
		if err != nil {
			return auth.ConnectionList{Connections: []auth.Connection{}}, unavailable()
		}
		list.Connections = append(list.Connections, record)
	}
	return list, nil
}

// GetConnection is a read: no advisory key, no success event, and an unknown
// reference fails without one. A denied attempt is recorded as connection.get.
func (s *LocalAuth) GetConnection(ctx context.Context, previous auth.Session, ref string) (auth.Connection, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var record auth.Connection
	if !validSession(previous) {
		return record, &auth.Error{Code: auth.Unauthenticated}
	}
	if err := s.ready(ctx); err != nil {
		return record, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return record, unavailable()
	}
	defer rollback(ctx, tx)
	if _, err := authorize(ctx, tx, previous, string(auth.EventConnectionGet)); err != nil {
		return record, err
	}
	row, err := findConnection(ctx, sqlc.New(tx), ref, false)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.ConnectionNotFound {
			return record, failure
		}
		return record, unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return record, unavailable()
	}
	record, err = connectionRecord(row)
	if err != nil {
		return auth.Connection{}, unavailable()
	}
	return record, nil
}
