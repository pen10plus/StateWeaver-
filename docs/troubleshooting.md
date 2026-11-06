# Troubleshooting & Operational Guide

## Common Issues & Solutions

### 1. `Scope violation: external target disallowed by localhost-only policy`
- **Cause:** By default, StateWeaver restricts all outgoing probe requests to `localhost`, `127.0.0.1`, and `::1` to prevent accidental scanning of external or production targets.
- **Solution:** If testing an authorized staging server (e.g. `api.staging.internal`), add the host to your scope and pass the `--allow-external` flag:
  ```bash
  stateweaver scope add api.staging.internal:8080
  stateweaver test --allow-external --target http://api.staging.internal:8080
  ```

### 2. `Mutation blocked: read-only mode active`
- **Cause:** To prevent accidental deletion or data modification during test runs, `read_only: true` is enabled by default or set via `--read-only`.
- **Solution:** When ready to test destructive verbs (`DELETE`, `PUT`, `PATCH`, `POST`), explicitly run without read-only:
  ```bash
  stateweaver test --read-only=false
  ```

### 3. `no imported records found`
- **Cause:** Running `stateweaver analyze` or `stateweaver test` before importing traffic.
- **Solution:** Ingest a HAR capture first:
  ```bash
  stateweaver import examples/sample_traffic.har
  ```

### 4. Build VCS Warning on Windows
- If building in an environment where git is not accessible in the current shell:
  ```bash
  go build -buildvcs=false ./...
  ```

