# TEST_OUTPUT.md

**Test file:** `src/tests/part2.test.ts`

## Before fixes (commit `e474f1e`)

```text
RUN v2.1.8 C:/QA/q-taskboard-assessment

× src/tests/part2.test.ts > task access control > a viewer cannot update a task
  → Test timed out in 5000ms.

× src/tests/part2.test.ts > task access control > a viewer cannot create a task
  → expected 403 to be 401

✓ src/tests/part2.test.ts > task access control > a member can create a task

Failed Tests: 2

Test Files  1 failed (1)
Tests       2 failed | 1 passed (3)
```

## After fixes (commit `15b2477`)

```text
RUN v2.1.8 C:/QA/q-taskboard-assessment

✓ src/tests/part2.test.ts > task access control > a viewer cannot update a task
✓ src/tests/part2.test.ts > task access control > a viewer cannot create a task
✓ src/tests/part2.test.ts > task access control > a member can create a task

Test Files  1 passed (1)
Tests       3 passed (3)
```

## What changed between the runs

- `api/tasks/[id]/route.ts`: PATCH now checks project membership and role. Viewers receive 403 Forbidden instead of being allowed to update tasks.
- `part2.test.ts`: The viewer-create test now expects 403 instead of 401. An authenticated viewer is forbidden from the action, not unauthenticated.
- Test and hook timeouts were increased because development-mode requests and logins were taking 3–5 seconds.
- `api/projects/[id]/tasks/route.ts`: Search using `?q=` is now parameterized to prevent SQL injection. This is documented separately in `BUGS.md` and is not covered by Part 2 tests.