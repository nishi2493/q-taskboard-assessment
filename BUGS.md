# BUGS.md — TaskBoard Bug Report (Part 1)

Top 4 findings, ordered by business impact. File and line references are against the original, unfixed code (commit `8b59efc`), before Part 2 changes.

| # | Finding | Category | Severity |
|---|---|---|---|
| 1 | SQL injection in task search | Security | Critical |
| 2 | Missing authorization in task update endpoint (PATCH) | Security | High |
| 3 | Project details API exposes users' password hashes | Security | High |
| 4 | Duplicate and case-variant email registrations allowed | Data Integrity | Medium |

**Ranking rationale:** SQL injection is ranked first because it may allow manipulation of database queries and unauthorized data access. Missing authorization on PATCH allows users to modify tasks without the required project permissions. Password hash exposure creates a risk of credential compromise. Duplicate email registration can cause account duplication and inconsistent identity management.

## 1. SQL injection in task search

- **File:** `src/app/api/projects/[id]/tasks/route.ts`
- **Lines:** 23–36 (particularly lines 27–34)
- **Category:** Security
- **Severity:** Critical

The `q` query parameter is directly interpolated into a raw SQL query using `ILIKE` and executed through `$queryRawUnsafe` without parameterization. This makes the endpoint vulnerable to SQL injection, potentially allowing an authenticated user to manipulate the query and access data beyond the intended project scope. A search term containing special SQL characters may also cause unexpected query errors.

**Reproduce**

```bash
# 1a. Test handling of an apostrophe in the search parameter
curl -i -s -H "Authorization: Bearer $DEV" \
  "$BASE/api/projects/$PID/tasks?q=it's"

# 1b. Test whether Boolean SQL injection bypasses search restrictions
curl -s -G -H "Authorization: Bearer $DEV" \
  --data-urlencode "q=zzz%') OR 1=1 --" \
  "$BASE/api/projects/$PID/tasks"

# 1c. Test whether UNION injection can expose user information
curl -s -G -H "Authorization: Bearer $DEV" \
  --data-urlencode "q=zzz%') UNION SELECT id, id, email, password_hash, NULL, NULL, NULL, 0, created_at, updated_at FROM users --" \
  "$BASE/api/projects/$PID/tasks"
```

**Expected:** Search input should be safely parameterized. Special characters should not cause SQL errors, and users should only receive tasks belonging to the requested project that they are authorized to access.

**Recommendation:** Replace unsafe raw SQL interpolation with parameterized queries and enforce project-level authorization independently of search conditions.

## 2. Missing authorization in task update endpoint (PATCH)

- **File:** `src/app/api/tasks/[id]/route.ts`
- **Lines:** 16–38 (PATCH handler)
- **Category:** Security — Broken Access Control / IDOR
- **Severity:** High

The PATCH endpoint checks whether the user is authenticated but does not verify their membership or role in the project associated with the task. Consequently, a viewer or a user who is not a member of the project may be able to modify its tasks by providing a valid task ID. This can result in unauthorized changes to task details, status, assignee, and position.

**Reproduce**

```bash
# 2a. Viewer attempts to update a task
curl -i -s -X PATCH \
  -H "Authorization: Bearer $DEV" \
  -H "Content-Type: application/json" \
  -d '{"title":"edited by a viewer"}' \
  "$BASE/api/tasks/$TID"

# 2b. Non-member attempts to update the same task
curl -i -s -X PATCH \
  -H "Authorization: Bearer $LINA" \
  -H "Content-Type: application/json" \
  -d '{"status":"done"}' \
  "$BASE/api/tasks/$TID"
```

**Expected:** Both requests should return `403 Forbidden` because neither user has permission to update the task. This authorization behaviour is also covered by Test A in `src/tests/part2.test.ts`.

**Recommendation:** Verify the task's associated project membership and the user's role before allowing any update. Apply the appropriate permission check consistently across task operations.

## 3. Project details API exposes users' password hashes

- **File:** `src/app/api/projects/[id]/route.ts`
- **Lines:** 25–40 (GET handler)
- **Category:** Security — Sensitive Data Exposure
- **Severity:** High

The project details query includes complete User records through relations such as `owner`, `members`, `assignee`, and `createdBy`, instead of selecting only the required fields. Consequently, sensitive information such as `passwordHash` may be included in the API response and exposed to authenticated project members. Attackers obtaining these hashes could attempt offline password cracking.

**Reproduce**

```bash
curl -s -H "Authorization: Bearer $DEV" \
  "$BASE/api/projects/$PID" \
  | grep -o '"passwordHash":"[^"]*"' | head -5
```

**Expected:** The API response should not contain `passwordHash` or other authentication-related information.

**Recommendation:** Use Prisma `select` to return only necessary user fields, such as `id`, `name`, and `email`, instead of returning complete User records.

## 4. Duplicate and case-variant email registrations allowed

- **File:** `prisma/schema.prisma` — line 25
- **File:** `src/app/api/auth/register/route.ts` — lines 17–26
- **File:** `src/app/api/auth/login/route.ts` — line 16
- **Category:** Data Integrity
- **Severity:** Medium

The email field does not have a database-level unique constraint, and registration relies on an application-level `findFirst` check before inserting a new user. Without email normalization and database-enforced uniqueness, case variants of an existing email may be registered as separate accounts, while concurrent registration requests may also create duplicate records. This can lead to account confusion and inconsistent authentication behaviour.

**Reproduce**

```bash
# 4a. Attempt registration using a case variant of an existing email
curl -i -s -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"MEERA@taskboard.dev","name":"Fake Meera","password":"password123"}'

# 4b. Attempt concurrent registrations using the same new email
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "$BASE/api/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"race@example.com","name":"Race","password":"password123"}' &
done
wait
```

**Expected:** Duplicate email registrations should be rejected, including case variants. Concurrent requests should not result in duplicate user records.

**Recommendation:** Normalize email addresses to lowercase before registration and login. Enforce uniqueness using a database-level unique constraint and handle duplicate-registration errors appropriately.