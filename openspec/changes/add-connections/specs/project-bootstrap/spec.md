## ADDED Requirements

### Requirement: Required encryption key configuration

Server configuration SHALL include `CLAVIS_ENCRYPTION_KEY_FILE`, an absolute path to a protected regular file containing 64 hexadecimal characters and at most one terminal newline. The setting SHALL be required from this change onward; configuration loading SHALL fail before listening with a predictable error naming the setting and one of `REQUIRED`, `INVALID_PATH`, `UNREADABLE`, `UNSAFE_PERMISSIONS` or `INVALID_KEY`, without printing the path contents or the key. The key SHALL be read once at startup and held in memory; the file MAY be removed afterwards without affecting the running process. `.env.example` SHALL document the setting and the generation command. The CLI SHALL NOT require or read the key.

#### Scenario: Missing or unsafe key file
- **WHEN** the server starts without the setting, with a group-readable file, or with a file of the wrong length
- **THEN** it exits nonzero with the documented configuration error before opening the listener or the database

#### Scenario: Key file removed after start
- **WHEN** the file is deleted while the server runs
- **THEN** connection operations keep working with the key held in memory and the next restart fails with `REQUIRED` or `UNREADABLE` until the file is restored

#### Scenario: Development setup
- **WHEN** a developer follows the README quick start
- **THEN** the documented command generates a key file with owner-only permissions and `make dev` starts with it
