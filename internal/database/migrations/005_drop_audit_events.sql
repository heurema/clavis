-- +goose Up
-- The audit journal leaves the MVP; nothing reads this table any more.
DROP TABLE auth_events;
