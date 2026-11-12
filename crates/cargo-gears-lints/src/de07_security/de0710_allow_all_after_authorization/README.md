# DE0710: `allow_all()` After Authorization

## What it does

Flags `AccessScope::allow_all()` used after a PDP-compiled `AccessScope` has been awaited in the same function body. A prefetch with `allow_all()` before the PDP call — loading the row to build the PDP request, the pattern the SDK documents — is not flagged; DE0709 covers a prefetched row returned while the scope is ignored.

## Why is this bad?

The function already knows which rows the caller may touch, then reads or writes with an unrestricted scope. If the id next to `allow_all()` comes from the request, the PDP decision does not cover it.

## When it is fine

Structural reads that must see rows outside the caller's scope (ancestor walks, invariant checks). Mark them explicitly:

```rust
#[expect(de0710_allow_all_after_authorization, reason = "ancestor walk for the depth invariant")]
```
