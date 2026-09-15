## MODIFIED Requirements

### Requirement: Encrypted credentials at rest

The server SHALL require `CLAVIS_ENCRYPTION_KEY_FILE`, an absolute path to a protected regular file holding exactly 32 key bytes encoded as 64 hexadecimal characters with at most one terminal newline, read with the same type, size and permission rules as the bootstrap password file, including the group rule defined in project-bootstrap. Startup SHALL fail before listening when the setting is absent, unreadable or invalid. Connection secrets SHALL be encrypted with AES-256-GCM using a fresh random 96-bit nonce per write, the connection UUID and key version as associated data, and stored as a versioned envelope. Plaintext secrets SHALL exist in memory only during creation, credential replacement and a connectivity check, and SHALL never be returned by any route, rendered in HTML or logged. A stored envelope that cannot be decrypted SHALL make the dependent operation fail closed with `CREDENTIALS_UNAVAILABLE` without affecting readiness.

#### Scenario: Server starts without a key
- **WHEN** the server starts with no `CLAVIS_ENCRYPTION_KEY_FILE`, a file readable by others or by a group the process does not belong to, a wrong length or a non-hexadecimal value
- **THEN** it exits with a configuration error naming the setting and the category, without listening and without reading the database

#### Scenario: Secret round trip
- **WHEN** a secret is stored and later used by a connectivity check
- **THEN** the check receives the original plaintext and the stored column holds only the versioned ciphertext, which differs between two writes of the same plaintext

#### Scenario: Envelope moved between rows or key changed
- **WHEN** a ciphertext is copied to another connection's row, or the key file is replaced with a different key
- **THEN** decryption fails, the operation reports `CREDENTIALS_UNAVAILABLE` and readiness remains unaffected

#### Scenario: Secret in an internal error
- **WHEN** a probe or driver error contains a sentinel secret or the target host
- **THEN** neither responses, logs nor CLI output contain them
