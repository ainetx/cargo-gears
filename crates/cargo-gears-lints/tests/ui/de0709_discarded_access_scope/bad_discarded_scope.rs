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
fn find_by_id(_scope: &AccessScope, _id: u32) {}

async fn create(parent_id: u32) -> Result<(), Denied> {
    // Should trigger DE0709 - discarded access scope: bound to a discarded name
    let _scope = authorize(parent_id).await?;
    find_by_id(&AccessScope::allow_all(), parent_id);
    Ok(())
}

async fn wildcard(id: u32) -> Result<(), Denied> {
    // Should trigger DE0709 - discarded access scope: bound to a discarded name
    let _ = authorize(id).await?;
    Ok(())
}

async fn statement(id: u32) -> Result<(), Denied> {
    // Should trigger DE0709 - discarded access scope: dropped as a statement
    authorize(id).await?;
    Ok(())
}

async fn matched(id: u32) -> bool {
    match authorize(id).await {
        // Should trigger DE0709 - discarded access scope: matched without being bound
        Ok(_) => true,
        Err(Denied) => false,
    }
}

async fn if_let(id: u32) -> bool {
    // Should trigger DE0709 - discarded access scope: matched without being bound
    if let Ok(_) = authorize(id).await {
        true
    } else {
        false
    }
}

async fn boolean(id: u32) -> bool {
    // Should trigger DE0709 - discarded access scope: reduced to a boolean
    authorize(id).await.is_ok()
}

fn main() {}
