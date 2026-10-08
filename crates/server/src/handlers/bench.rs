use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use sea_orm::{sea_query::value::prelude::chrono::SecondsFormat, sqlx::types::chrono::Utc};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: u32,
    username: String,
    display_name: String,
}

#[derive(Deserialize)]
struct CreateMessage {
    content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    id: u32,
    user_id: u32,
    content: String,
    created_at: String,
}

type Users = Arc<Vec<User>>;

pub fn router() -> Router<AppState> {
    let users: Users = Arc::new(
        (1..=100)
            .map(|i| User {
                id: i,
                username: format!("user{i}"),
                display_name: format!("User {i}"),
            })
            .collect(),
    );

    Router::new()
        .route("/users", get(list_users))
        .route("/messages", post(create_message))
        .with_state(users)
}

async fn list_users(State(users): State<Users>) -> Json<Users> {
    Json(users)
}

async fn create_message(Json(body): Json<CreateMessage>) -> Json<Message> {
    Json(Message {
        id: 1,
        user_id: 1,
        content: body.content,
        // Matches JS `new Date().toISOString()` (millisecond precision, trailing Z)
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}
