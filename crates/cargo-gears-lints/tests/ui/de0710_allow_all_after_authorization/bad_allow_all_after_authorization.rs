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
    let scope = authorize(parent_id).await?;
    find_by_id(&scope, 0);
    // Should trigger DE0710 - allow_all after authorization: allow_all after a PDP-compiled scope
    find_by_id(&AccessScope::allow_all(), parent_id);
    Ok(())
}

fn main() {}
