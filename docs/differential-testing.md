# Differential Authorization Testing Methodology

Traditional vulnerability scanners analyze API endpoints in isolation, sending synthetic attack vectors (such as SQL injection patterns or script tags) and observing error messages. 

However, modern API vulnerabilities—specifically **Broken Object Level Authorization (BOLA/IDOR)**, **cross-tenant access leaks**, **privilege escalations**, and **revoked credential retention**—do not trigger syntax errors or crashes. The application responds with a normal `HTTP 200 OK` and a valid JSON response.

StateWeaver uses **Differential Authorization Testing** to detect these logic flaws.

---

## The Differential Matrix

StateWeaver constructs a matrix comparing multiple identities interacting with the same operation and resource:

| Test Identity | Role | Tenant | Expected Policy | Vulnerable API Result | Secure API Result |
|---|---|---|---|---|---|
| **Alice (Baseline)** | Owner | `org-a` | Allow (200 OK) | 200 OK (Baseline) | 200 OK (Baseline) |
| **Bob** | Viewer | `org-a` | Deny on Mutation / Secrets | 204 No Content (DELETE) ⚠️ | 403 Forbidden |
| **Charlie** | Member | `org-b` | Deny on Org-A Resources | 200 OK (BOLA Exposure) ⚠️ | 404 / 403 Forbidden |
| **Dave** | Member (Revoked) | `org-a` | Deny All | 200 OK (Stale Token) ⚠️ | 401 Unauthorized |
| **Anonymous** | Guest | None | Deny Protected | 200 OK (Unprotected) ⚠️ | 401 Unauthorized |

---

## Why Naive Comparison Fails (and How StateWeaver Solves It)

A naive diff between two HTTP responses will almost always detect differences due to:
1. Dynamic timestamps (`created_at`, `timestamp`).
2. Volatile transaction IDs (`request_id`, `trace_id`).
3. Anti-CSRF tokens and nonces.

StateWeaver solves this by:
- Normalizing dynamic values into canonical tokens (`<TIMESTAMP>`, `<UUID>`, `<DYNAMIC_VALUE>`) before comparison.
- Requiring an **explicit policy rule match** before any difference is classified as a vulnerability.
- Distinguishing between collection listing endpoints (where a tenant user can legitimately view their own items) and specific entity endpoints.

