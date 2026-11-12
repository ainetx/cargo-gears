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
fn find_by_id(_scope: &AccessScope, _id: u32) {}

fn system_job(id: u32) {
    // Should not trigger DE0710 - allow_all after authorization: no PDP decision in this function
    find_by_id(&AccessScope::allow_all(), id);
}

#[expect(
    de0710_allow_all_after_authorization,
    reason = "ancestor walk for an invariant check"
)]
async fn documented(id: u32) -> Result<(), Denied> {
    // Should not trigger DE0710 - allow_all after authorization: explicitly justified
    let scope = authorize(id).await?;
    find_by_id(&scope, id);
    find_by_id(&AccessScope::allow_all(), 0);
    Ok(())
}

async fn prefetch_then_authorize(id: u32) -> Result<(), Denied> {
    // Should not trigger DE0710 - allow_all after authorization: prefetch before the PDP call
    find_by_id(&AccessScope::allow_all(), id);
    let scope = authorize(id).await?;
    find_by_id(&scope, id);
    Ok(())
}

fn main() {}
