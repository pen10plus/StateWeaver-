# StateWeaver — Differential Authorization Security Report

**Project:** `stateweaver-project` | **Version:** `1.0.0` | **Date:** `2026-11-06T10:11:26Z`

## Executive Summary

- **Total Findings:** 10
- **Critical:** 6 | **High:** 4 | **Medium:** 0 | **Low:** 0
- **In-Scope Targets:** `localhost, 127.0.0.1, ::1, localhost:8080, 127.0.0.1:8080, localhost:8081, 127.0.0.1:8081, 127.0.0.1:8080`

## Findings Detail

### 1. [Critical] Cross-Tenant Access Weakness — GET http://127.0.0.1:8080/api/projects

- **Finding ID:** `SW-FINDING-0001`
- **Affected Identity:** `Charlie (Member Org-B) (Role: member, Tenant: org-b)`
- **Resource:** `project`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>" \
  -H "X-Tenant-ID: org-b"
```

#### Defensive Remediation

> Enforce strict tenant_id scoping in database queries and verify tenant membership from authenticated session token.

---

### 2. [Critical] Revoked-Access Inconsistency — GET http://127.0.0.1:8080/api/projects

- **Finding ID:** `SW-FINDING-0002`
- **Affected Identity:** `Dave (Revoked Member) (Role: member, Tenant: org-a)`
- **Resource:** `project`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>" \
  -H "X-Tenant-ID: org-a"
```

#### Defensive Remediation

> Check real-time revocation status in database/cache rather than relying solely on non-expiring JWT claims.

---

### 3. [High] Broken Authentication — GET http://127.0.0.1:8080/api/projects

- **Finding ID:** `SW-FINDING-0003`
- **Affected Identity:** `Anonymous User (Role: anonymous, Tenant: )`
- **Resource:** `project`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>"
```

#### Defensive Remediation

> Enforce authentication middleware on all private API routes.

---

### 4. [Critical] Cross-Tenant Access Weakness — GET http://127.0.0.1:8080/api/projects/1001

- **Finding ID:** `SW-FINDING-0004`
- **Affected Identity:** `Charlie (Member Org-B) (Role: member, Tenant: org-b)`
- **Resource:** `project`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Response payload matches baseline data (Potential Unauthorized Data Exposure); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects/1001" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>" \
  -H "X-Tenant-ID: org-b"
```

#### Defensive Remediation

> Enforce strict tenant_id scoping in database queries and verify tenant membership from authenticated session token.

---

### 5. [Critical] Revoked-Access Inconsistency — GET http://127.0.0.1:8080/api/projects/1001

- **Finding ID:** `SW-FINDING-0005`
- **Affected Identity:** `Dave (Revoked Member) (Role: member, Tenant: org-a)`
- **Resource:** `project`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Response payload matches baseline data (Potential Unauthorized Data Exposure); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects/1001" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>" \
  -H "X-Tenant-ID: org-a"
```

#### Defensive Remediation

> Check real-time revocation status in database/cache rather than relying solely on non-expiring JWT claims.

---

### 6. [High] Broken Authentication — GET http://127.0.0.1:8080/api/projects/1001

- **Finding ID:** `SW-FINDING-0006`
- **Affected Identity:** `Anonymous User (Role: anonymous, Tenant: )`
- **Resource:** `project`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Response payload matches baseline data (Potential Unauthorized Data Exposure); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects/1001" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>"
```

#### Defensive Remediation

> Enforce authentication middleware on all private API routes.

---

### 7. [Critical] Cross-Tenant Access Weakness — GET http://127.0.0.1:8080/api/projects/1001/secrets

- **Finding ID:** `SW-FINDING-0007`
- **Affected Identity:** `Charlie (Member Org-B) (Role: member, Tenant: org-b)`
- **Resource:** `secret`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Response payload matches baseline data (Potential Unauthorized Data Exposure); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects/1001/secrets" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>" \
  -H "X-Tenant-ID: org-b"
```

#### Defensive Remediation

> Enforce strict tenant_id scoping in database queries and verify tenant membership from authenticated session token.

---

### 8. [Critical] Revoked-Access Inconsistency — GET http://127.0.0.1:8080/api/projects/1001/secrets

- **Finding ID:** `SW-FINDING-0008`
- **Affected Identity:** `Dave (Revoked Member) (Role: member, Tenant: org-a)`
- **Resource:** `secret`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Response payload matches baseline data (Potential Unauthorized Data Exposure); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects/1001/secrets" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>" \
  -H "X-Tenant-ID: org-a"
```

#### Defensive Remediation

> Check real-time revocation status in database/cache rather than relying solely on non-expiring JWT claims.

---

### 9. [High] Broken Authentication — GET http://127.0.0.1:8080/api/projects/1001/secrets

- **Finding ID:** `SW-FINDING-0009`
- **Affected Identity:** `Anonymous User (Role: anonymous, Tenant: )`
- **Resource:** `secret`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 200 200 OK

#### Evidence & Difference Analysis

```
Status codes match (200); Response payload matches baseline data (Potential Unauthorized Data Exposure); Sensitive fields exposed: secrets
```

#### Safe Reproduction Steps

```bash
curl -i -X GET "http://127.0.0.1:8080/api/projects/1001/secrets" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>"
```

#### Defensive Remediation

> Enforce authentication middleware on all private API routes.

---

### 10. [High] Role-Based Authorization Flaw — DELETE http://127.0.0.1:8080/api/projects/1001

- **Finding ID:** `SW-FINDING-0010`
- **Affected Identity:** `Bob (Viewer) (Role: viewer, Tenant: org-a)`
- **Resource:** `project`
- **Validation Status:** `Confirmed` (Confidence: `High`)
- **Expected Behavior:** Access DENY (Expected HTTP [401 403 404])
- **Observed Behavior:** Access allowed with HTTP 204 204 No Content

#### Evidence & Difference Analysis

```
Status codes match (204); Response payload matches baseline data (Potential Unauthorized Data Exposure)
```

#### Safe Reproduction Steps

```bash
curl -i -X DELETE "http://127.0.0.1:8080/api/projects/1001" \
  -H "Authorization: Bearer <TEST_IDENTITY_TOKEN>" \
  -H "X-Tenant-ID: org-a"
```

#### Defensive Remediation

> Ensure role-based permission checks verify DELETE permission before executing project deletion.

---

