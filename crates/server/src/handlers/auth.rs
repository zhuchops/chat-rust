use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use garde::Validate;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, EntityTrait, IntoActiveModel,
    QueryFilter, QuerySelect, TransactionTrait, sqlx::types::chrono::Utc,
};
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    auth_helpers::{
        jwt::sign_access_token,
        session::create_session,
        tokens::{generate_refresh_token, hash_token},
    },
    entity::{
        sessions::{
            self,
            Column::{PreviousTokenHash, RefreshTokenHash},
        },
        users,
    },
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh))
}

#[derive(Serialize)]
struct Message {
    message: String,
}

#[derive(Serialize)]
struct LoginRegisterReturnUser {
    id: i32,
    email: String,
    username: String,
}

#[derive(Serialize)]
struct LoginRegisterResult {
    refresh_token: String,
    access_token: String,
    user: LoginRegisterReturnUser,
}

#[derive(Serialize)]
struct LoginRegisterReturn {
    message: Message,
    result: LoginRegisterResult,
}

#[derive(Serialize)]
struct RefreshResult {
    access_token: String,
    refresh_token: String,
}

#[derive(Serialize)]
struct RefreshReturn {
    message: Message,
    result: RefreshResult,
}

#[derive(Deserialize, Validate)]
struct RegisterInput {
    #[garde(email)]
    email: String,
    #[garde(length(min = 1))]
    username: String,
    #[garde(length(min = 1))]
    password: String,
}

#[derive(Deserialize, Validate)]
struct LoginInput {
    #[garde(email)]
    email: String,
    #[garde(length(min = 1))]
    password: String,
}

#[derive(Deserialize, Validate)]
struct RefreshLogoutInput {
    #[garde(length(min = 1))]
    refresh_token: String,
}

async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterInput>,
) -> Result<(StatusCode, Json<LoginRegisterReturn>), (StatusCode, Json<Message>)> {
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(body.password.as_bytes())
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Message {
                    message: "internal server error while hashing password".into(),
                }),
            )
        })?
        .to_string();
    let user = users::ActiveModel::builder()
        .set_email(body.email)
        .set_username(body.username)
        .set_password_hash(password_hash)
        .insert(&state.db)
        .await
        .map_err(|e| {
            eprintln!("register error: {e:?}");
            (
                StatusCode::CONFLICT,
                Json(Message {
                    message: "user with such email or username already exists".into(),
                }),
            )
        })?;

    let refresh_token = generate_refresh_token();
    create_session(state.clone(), user.id, &refresh_token)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Message {
                    message: "failed to create session".into(),
                }),
            )
        })?;
    let access_token = sign_access_token(state.config.as_ref(), user.id).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "failed to sign access token".into(),
            }),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(LoginRegisterReturn {
            message: Message {
                message: "created".into(),
            },
            result: LoginRegisterResult {
                refresh_token: refresh_token,
                access_token: access_token,
                user: LoginRegisterReturnUser {
                    id: user.id,
                    email: user.email,
                    username: user.username,
                },
            },
        }),
    ))
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginInput>,
) -> Result<(StatusCode, Json<LoginRegisterReturn>), (StatusCode, Json<Message>)> {
    // find user
    let user = users::Entity::find_by_email(body.email)
        .require_one(&state.db)
        .await
        .map_err(|e| {
            eprintln!("error while login: {e:?}");
            (
                StatusCode::UNAUTHORIZED,
                Json(Message {
                    message: "bad email or password".into(),
                }),
            )
        })?;

    let argon2 = Argon2::default();

    // compare two hashes
    match argon2.verify_password(body.password.as_bytes(), user.password_hash.as_str()) {
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(Message {
                    message: "bad email or password".into(),
                }),
            ));
        }
        Ok(_) => {}
    }

    let refresh_token = generate_refresh_token();
    create_session(state.clone(), user.id, &refresh_token)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Message {
                    message: "failed to create session".into(),
                }),
            )
        })?;
    let access_token = sign_access_token(state.config.as_ref(), user.id).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "failed to sign access token".into(),
            }),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(LoginRegisterReturn {
            message: Message {
                message: "ok".into(),
            },
            result: LoginRegisterResult {
                refresh_token: refresh_token,
                access_token: access_token,
                user: LoginRegisterReturnUser {
                    id: user.id,
                    email: user.email,
                    username: user.username,
                },
            },
        }),
    ))
}

async fn logout(
    State(state): State<AppState>,
    Json(body): Json<RefreshLogoutInput>,
) -> Result<(StatusCode, Json<Message>), (StatusCode, Json<Message>)> {
    let hash = hash_token(&body.refresh_token);
    sessions::Entity::delete_by_refresh_token_hash(hash)
        .exec(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(Message {
                    message: "no such session found".into(),
                }),
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(Message {
            message: "successfully deleted session".into(),
        }),
    ))
}

async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshLogoutInput>,
) -> Result<(StatusCode, Json<RefreshReturn>), (StatusCode, Json<Message>)> {
    let txn = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "cannot begin transaction".into(),
            }),
        )
    })?;
    let old_hash = hash_token(&body.refresh_token);
    let session = sessions::Entity::find()
        .filter(
            Condition::any()
                .add(RefreshTokenHash.eq(&old_hash))
                .add(PreviousTokenHash.eq(&old_hash)),
        )
        .lock_exclusive()
        .require_one(&txn)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(Message {
                    message: "no such session found".into(),
                }),
            )
        })?;

    if session.revoked_at.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Message {
                message: "SESSION COMPAMISED!!!".into(),
            }),
        ));
    }

    let now = Utc::now();

    if session.expires_at <= now {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Message {
                message: "session expired. login again".into(),
            }),
        ));
    }

    let is_current = session.refresh_token_hash == old_hash;

    if !is_current {
        let within_grace = session
            .rotated_at
            .map_or(false, |t| now - t <= state.config.refresh_token_grace_time);

        if !within_grace {
            let mut session: sessions::ActiveModel = session.into();
            session.revoked_at = Set(Some(now));
            session.update(&txn).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Message {
                        message: "cannot revoke session".into(),
                    }),
                )
            })?;
            txn.commit().await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Message {
                        message: "cannot end transaction".into(),
                    }),
                )
            })?;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(Message {
                    message: "TOKEN COMPROMISED!!!".into(),
                }),
            ))?;
        }
    }

    let new_refresh_token = generate_refresh_token();
    let mut session = session.into_active_model();
    session.previous_token_hash = Set(Some(session.refresh_token_hash.unwrap()));
    session.refresh_token_hash = Set(hash_token(&new_refresh_token));
    session.rotated_at = Set(Some(now));
    session.expires_at = Set(now + state.config.refresh_token_lifetime);
    let session = session.update(&txn).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "cannot update session".into(),
            }),
        )
    })?;

    txn.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "cannot end transaction".into(),
            }),
        )
    })?;

    let new_access_token = sign_access_token(&state.config, session.user_id).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "failed to sign access token".into(),
            }),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(RefreshReturn {
            message: Message {
                message: "successfully updated session".into(),
            },
            result: RefreshResult {
                access_token: new_access_token,
                refresh_token: new_refresh_token,
            },
        }),
    ))
}
