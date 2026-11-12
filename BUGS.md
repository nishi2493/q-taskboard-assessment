# BUGS.md — TaskBoard bug report (Part 1)

Top 4 findings, ordered by business impact. File and line references are against the **original vulnerable code** (commit `e474f1e`), before the security fixes were applied.

| # | Finding | Category | Severity |
|---|---------|----------|----------|
| 1 | SQL injection in task search | Security | Critical |
| 2 | Any logged-in user can edit any task (no membership/role check on PATCH) | Security | High |
| 3 | `GET /api/projects/:id` returns every member's `passwordHash` | Security | High |
| 4 | Duplicate / case-variant email accounts allowed (no unique constraint) | Data Integrity | Medium |

**Ranking rationale:** #1 gives full database read access to any project member (including a viewer), a superset of #3. #2 lets anyone tamper with other teams' data. #3 hands out credential material with a plain GET. #4 corrupts the identity model but needs more effort to exploit.

No UI-only findings were included; all four were found by reading the code and confirmed through the API.

**Evidence note:** Bugs 1 and 2 were captured against commit `e474f1e`, before the security fixes were applied. The curl outputs below must be captured from that original vulnerable revision. Do not substitute results from the fixed `main` branch.

## Setup for the curl proofs

Run in **Git Bash** (not `cmd`). The app and seeded DB must be running. Seed users: `dev@example.com` is a **viewer** on Q3 Launch, `lina@example.com` is **not a member** of Q3 Launch.

```bash
BASE=http://localhost:3000
login() { curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" \
  -d "{\"email\":\"$1\",\"password\":\"password123\"}" | sed -E 's/.*"token":"([^"]+)".*/\1/'; }

DEV=$(login dev@example.com)
LINA=$(login lina@example.com)
PID=$(curl -s -H "Authorization: Bearer $DEV" $BASE/api/projects | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
TID=$(curl -s -H "Authorization: Bearer $DEV" $BASE/api/projects/$PID/tasks | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "project=$PID task=$TID"
```

Re-run `npm run db:seed` after the proofs to restore the seeded data.

---

## 1. SQL injection in task search

- **File:** `src/app/api/projects/[id]/tasks/route.ts`, lines 23–36 (string-built query on lines 27–33, executed with `$queryRawUnsafe` on line 34)
- **Category:** Security
- **Severity:** Critical

The `q` query parameter is interpolated straight into a raw SQL string (`ILIKE '%${q}%'`) and run with `$queryRawUnsafe`, with no parameterization. Any project member, including a read-only viewer, can break out of the query to read tasks from every project and, with a `UNION`, any other table such as `users` (emails and password hashes). A simple apostrophe in a normal search also crashes the endpoint with a 500.

**Reproduce**

```bash
# 1a. A plain apostrophe breaks the query -> expect HTTP 500 (should be 200)
curl -i -s -H "Authorization: Bearer $DEV" "$BASE/api/projects/$PID/tasks?q=it's"

# 1b. Boolean injection: returns tasks from EVERY project (dev is only a viewer on Q3 Launch)
curl -s -G -H "Authorization: Bearer $DEV" \
  --data-urlencode "q=zzz%') OR 1=1 --" "$BASE/api/projects/$PID/tasks"

# 1c. UNION injection: reads the users table (title = email, description = password hash)
curl -s -G -H "Authorization: Bearer $DEV" \
  --data-urlencode "q=zzz%') UNION SELECT id, id, email, password_hash, NULL, NULL, NULL, 0, created_at, updated_at FROM users --" \
  "$BASE/api/projects/$PID/tasks"
```

**Observed output — replace this section with the matching actual output from `proof-output.txt`:**

```text
[PASTE THE COMPLETE, MATCHING SECTIONS: ===== BUG 1a, ===== BUG 1b, AND ===== BUG 1c]
```

**Expected:** 1a returns 200 with no results; 1b and 1c return only matching tasks of this project.

---

## 2. Any logged-in user can edit any task (missing authorization on PATCH)

- **File:** `src/app/api/tasks/[id]/route.ts`, `PATCH` handler, lines 16–38 (no `getProjectMembership` / `canEditTasks` check between lines 20 and 29; compare `DELETE` on lines 49–53, which has it)
- **Category:** Security (broken access control / IDOR)
- **Severity:** High

`PATCH /api/tasks/:id` only checks that the caller is logged in. It never looks up the caller's membership in the task's project, so viewers can edit tasks and users who are not members of the project at all can rewrite its tasks (title, description, status, assignee, position). `DELETE` in the same file and `POST` on the project's task route both enforce the role check, which makes this an inconsistent, easy-to-miss gap.

**Reproduce**

```bash
# 2a. Viewer edits a task -> expect HTTP 200 (should be 403)
curl -i -s -X PATCH -H "Authorization: Bearer $DEV" -H "Content-Type: application/json" \
  -d '{"title":"edited by a viewer"}' $BASE/api/tasks/$TID

# 2b. Non-member edits a task of a project they do not belong to -> expect 200 (should be 403)
curl -i -s -X PATCH -H "Authorization: Bearer $LINA" -H "Content-Type: application/json" \
  -d '{"status":"done"}' $BASE/api/tasks/$TID
```

**Observed output — replace this section with the matching actual output from `proof-output.txt`:**

```text
[PASTE THE COMPLETE, MATCHING SECTIONS: ===== BUG 2a AND ===== BUG 2b]
```

**Expected:** both return `403 Forbidden`.

---

## 3. Project detail endpoint leaks every member's password hash

- **File:** `src/app/api/projects/[id]/route.ts`, `GET` handler, lines 25–40 (`owner: true` line 28, `include: { user: true }` line 30, `assignee: true` / `createdBy: true` lines 34–35)
- **Category:** Security (sensitive data exposure)
- **Severity:** High

The query includes whole `User` rows instead of selecting safe fields, so the JSON response contains `passwordHash` (plus email and timestamps) for the owner, every member, and every task assignee and creator. Any member of a project, including a viewer, can download these bcrypt hashes for offline cracking. The seeded accounts all use the weak password `password123`, so the risk is concrete.

**Reproduce**

```bash
curl -s -H "Authorization: Bearer $DEV" $BASE/api/projects/$PID \
  | grep -o '"passwordHash":"[^"]*"' | head -5
```

**Observed output — replace this section with the matching actual output from `proof-output.txt`:**

```text
[PASTE THE SECTION STARTING ===== BUG 3. Redact most hash characters if needed, but retain proof that passwordHash is present.]
```

**Expected:** no `passwordHash` anywhere in the response; use `select: { id, name, email }` for related users.

---

## 4. Duplicate and case-variant email accounts are allowed

- **File:** `prisma/schema.prisma` line 25 (`email String` with no `@unique`); `src/app/api/auth/register/route.ts` lines 17–26 (check-then-insert with `findFirst`); `src/app/api/auth/login/route.ts` line 16 (`findFirst` on a non-unique column)
- **Category:** Data Integrity
- **Severity:** Medium

Uniqueness of email is enforced only by an application-level `findFirst` before the insert, with no database unique constraint and no email normalization. `MEERA@taskboard.dev` registers as a separate account from `meera@taskboard.dev`, and two simultaneous registrations of the same email can both succeed. Because login uses `findFirst` on a non-unique column, which account a user lands in is not guaranteed, and look-alike accounts can be used to impersonate teammates.

**Reproduce**

```bash
# 4a. Case variant of an existing account -> expect HTTP 201 (should be 400/409)
curl -i -s -X POST $BASE/api/auth/register -H "Content-Type: application/json" \
  -d '{"email":"MEERA@taskboard.dev","name":"Fake Meera","password":"password123"}'

# 4b. Race: five parallel registrations of the same new email (may return several 201s)
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/api/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email":"race@example.com","name":"Race","password":"password123"}' &
done; wait
```

**Observed output — replace this section with the matching actual output from `proof-output.txt`:**

```text
[PASTE THE SECTION STARTING ===== BUG 4a. Include BUG 4b too if its output was captured.]
```

**Expected:** the second registration is rejected; emails are lower-cased on write and the column has a unique index.

---

## Also noticed (not in the top 4)

- **Performance:** `src/app/api/projects/route.ts` lines 16 and 29 load every task row of every project just to compute `taskCount`; `_count: { select: { tasks: true } }` would do this in the database.
- **Security:** `src/lib/jwt.ts` line 7 issues 30-day tokens with no revocation, and `src/lib/api-client.ts` lines 10 and 25 store the token in `localStorage`, where any XSS can read it.
- **Data integrity:** `assigneeId` is accepted without checking the assignee belongs to the project (`src/schemas/task.ts` lines 12 and 18), so a task can be assigned to an outsider, and the response then exposes that user's name and email.
