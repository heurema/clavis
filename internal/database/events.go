package database

import (
	"context"

	"github.com/heurema/clavis/internal/auth"
)

var _ auth.EventRecorder = (*LocalAuth)(nil)

func (s *LocalAuth) RecordEvent(ctx context.Context, event auth.Event) error {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	if !event.Valid() {
		return &auth.Error{Code: auth.InvalidArgument}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return unavailable()
	}
	defer rollback(ctx, tx)
	if err := audit(ctx, tx, event.ActorID, event.TargetID, event.SessionID, string(event.Action), string(event.Outcome)); err != nil {
		return unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable()
	}
	return nil
}
