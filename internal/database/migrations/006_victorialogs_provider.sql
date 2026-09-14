-- +goose Up
-- The provider registry gained a third member, and the column's check is the
-- storage half of that registry: without it no victorialogs connection can be
-- stored at all. The constraint is replaced rather than widened in place,
-- because a check constraint has no ALTER of its own.
ALTER TABLE connections DROP CONSTRAINT connections_provider_check;
ALTER TABLE connections ADD CONSTRAINT connections_provider_check
    CHECK (provider IN ('postgresql', 'victoriametrics', 'victorialogs'));
