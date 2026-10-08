mod auth_helpers;
mod entity;
mod handlers;
mod middlewares;

use axum::Router;
use chrono::Duration;
use dotenvy::dotenv;
use sea_orm::{Database, DatabaseConnection, sea_query::value::prelude::chrono};
use std::{env, error::Error, sync::Arc};

use crate::handlers::{auth, bench};

struct Config {
    jwt_secret: String,
    refresh_token_lifetime: Duration,
    refresh_token_grace_time: Duration,
    access_token_ttl_seconds: u64,
}

impl Config {
    fn from_env() -> Result<Self, env::VarError> {
        dotenv().ok();
        Ok(Self {
            jwt_secret: env::var("JWT_SECRET")?,
            refresh_token_lifetime: Duration::hours(30 * 24),
            refresh_token_grace_time: Duration::seconds(15),
            access_token_ttl_seconds: 15 * 60,
        })
    }
}

#[derive(Clone)]
struct AppState {
    db: DatabaseConnection,
    config: Arc<Config>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    let db = Database::connect(env::var("DATABASE_URL").unwrap()).await?;
    db.get_schema_registry("server::entity::*")
        .sync(&db)
        .await?;
    let config = Config::from_env().unwrap();
    let state = AppState {
        db: db,
        config: Arc::new(config),
    };

    let public = Router::new()
        .nest("/auth", auth::router())
        .nest("/bench", bench::router());
    // let protected = Router::new().route_layer(from_fn_with_state(state.clone(), auth_guard));

    let app = Router::new()
        // .nest("/api", protected)
        .merge(public)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
