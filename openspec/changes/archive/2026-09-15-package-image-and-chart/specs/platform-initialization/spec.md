## MODIFIED Requirements

### Requirement: Safe bounded bootstrap secret handling

The server SHALL read only a bounded regular password file with protected POSIX permissions: nothing granted to others, nothing but read granted to the group, and, when group-read is set, a group that is the process's effective group or one of its supplementary groups. Deployment-managed symlinks SHALL be supported while the opened target is validated. Directories, FIFOs, oversized input and unsafe permissions SHALL fail without blocking indefinitely. File/stdin input SHALL remove at most one terminal LF or CRLF and preserve other whitespace. Bootstrap SHALL share the username/password rules specified by local-authentication and the file permission rule specified for the encryption key in project-bootstrap, through one implementation. Only a versioned password hash SHALL be stored; secret contents and paths SHALL be absent from public output and logs.

#### Scenario: A projected secret is supplied
- **WHEN** the configured path is a symlink to a protected regular file containing a valid password and one terminal newline
- **THEN** bootstrap uses the password without that terminal newline and does not reject the path solely for being a symlink

#### Scenario: A Secret volume is mounted under the pod group
- **WHEN** the configured path is a file of mode `0440` whose group is the process's effective or a supplementary group
- **THEN** bootstrap reads the password and proceeds

#### Scenario: Credentials are unavailable or unsafe
- **WHEN** an uninitialized installation lacks one or both inputs, or the supplied file is invalid, unreadable, readable by others, group-writable or owned by a group the process does not belong to
- **THEN** no administrator is created and readiness distinguishes missing setup from failed bootstrap using safe application-owned text

#### Scenario: Secret data occurs in an internal error
- **WHEN** reading or hashing a bootstrap input fails with internal details containing a sentinel secret or file path
- **THEN** neither logs, HTTP responses nor CLI diagnostics contain those details
