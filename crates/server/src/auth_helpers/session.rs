use sea_orm::DbErr;
use sea_orm::sqlx::types::chrono::Utc;

use crate::auth_helpers::tokens::hash_token;
use crate::{AppState, entity::sessions};

pub async fn create_session(
    state: AppState,
    user_id: i32,
    refresh_token: &str,
) -> Result<(), DbErr> {
    let expires_at = Utc::now() + state.config.refresh_token_lifetime;
    sessions::ActiveModel::builder()
        .set_user_id(user_id)
        .set_refresh_token_hash(hash_token(refresh_token))
        .set_expires_at(expires_at)
        .insert(&state.db)
        .await?;
    Ok(())
}
