#![allow(dead_code, unused_variables)]

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

fn main() {}
