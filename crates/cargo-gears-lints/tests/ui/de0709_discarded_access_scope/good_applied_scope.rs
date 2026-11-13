#![allow(dead_code, unused_variables, unknown_lints)]

pub struct AccessScope;
impl AccessScope {
    pub fn allow_all() -> Self {
        AccessScope
    }
}
pub struct Denied;

async fn authorize(_id: u32) -> Result<AccessScope, Denied> {
    Ok(AccessScope)
}
async fn ping() -> Result<(), Denied> {
    Ok(())
}
fn find_by_id(_scope: &AccessScope, _id: u32) {}

async fn applied(id: u32) -> Result<(), Denied> {
    // Should not trigger DE0709 - discarded access scope: scope applied
    let scope = authorize(id).await?;
    find_by_id(&scope, id);
    Ok(())
}

async fn matched_and_bound(id: u32) -> Result<(), Denied> {
    // Should not trigger DE0709 - discarded access scope: scope bound in the arm
    match authorize(id).await {
        Ok(scope) => find_by_id(&scope, id),
        Err(denied) => return Err(denied),
    }
    Ok(())
}

async fn other_awaits() -> Result<(), Denied> {
    // Should not trigger DE0709 - discarded access scope: not a scope
    let _ = ping().await?;
    ping().await?;
    Ok(())
}

fn constructed() {
    // Should not trigger DE0709 - discarded access scope: not awaited, so not a PDP decision
    let _scope = AccessScope::allow_all();
}

#[cfg(test)]
mod tests {
    async fn in_tests() {
        let _scope = super::authorize(1).await;
    }
}

fn apply_scope(_scope: AccessScope) -> Result<(), Denied> {
    Ok(())
}

async fn applied_then_checked(id: u32) -> Result<bool, Denied> {
    // Should not trigger DE0709 - discarded access scope: `.is_ok()` inspects `apply_scope`'s result
    Ok(apply_scope(authorize(id).await?).is_ok())
}

async fn statement_level_expect(id: u32) -> Result<(), Denied> {
    #[expect(
        de0709_discarded_access_scope,
        reason = "gate-only check on a global resource"
    )]
    // Should not trigger DE0709 - discarded access scope: suppressed on the statement
    let _scope = authorize(id).await?;
    Ok(())
}

fn main() {}
