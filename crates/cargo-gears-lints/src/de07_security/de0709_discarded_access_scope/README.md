# DE0709: Discarded Access Scope

## What it does

Flags a PDP-compiled `AccessScope` (any awaited `AccessScope`, `Result<AccessScope, _>` or `Option<AccessScope>`) that is thrown away instead of applied:

- `let _scope = enforcer.access_scope_with(..).await?;` / `let _ = ...`
- `self.authorize(..).await?;` as a statement
- `match enforcer.access_scope(..).await { Ok(_) => .., Err(_) => .. }`, `if let Ok(_) = ...`
- `enforcer.access_scope(..).await.is_ok()`

## Why is this bad?

PDPs answer *allow, constrained to a scope* — typically the caller's own tenant or subtree. The scope is what binds the decision to the resource the request names. Dropping it reduces authorization to "may the caller do this to something", which becomes a cross-tenant bypass whenever the target id comes from the request.

## Fix

Apply the scope to the read or write (`repo.find_by_id(&scope, id)`), or check the request's id against it before acting.
