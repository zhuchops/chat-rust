use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{DecodingKey, Validation, decode, errors::ErrorKind::ExpiredSignature};
use serde::Deserialize;

use crate::AppState;

#[derive(Clone)]
pub struct UserId(pub i64);

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn auth_guard(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing token"))?;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::new(jsonwebtoken::Algorithm::HS256),
    )
    .map_err(|e| match e.kind() {
        ExpiredSignature => (StatusCode::UNAUTHORIZED, "token expired"),
        _ => (StatusCode::UNAUTHORIZED, "invalid token"),
    })?;

    let id: i64 = data
        .claims
        .sub
        .parse()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token"))?;

    req.extensions_mut().insert(UserId(id));

    Ok(next.run(req).await)
}
