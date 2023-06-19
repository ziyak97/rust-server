use crate::http::error::{Error, ResultExt};
use crate::http::extractor::AuthUser;
use crate::http::{ApiContext, Result};
use anyhow::Context;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_cookies::{Cookie, Cookies};

pub(crate) fn router() -> Router<ApiContext> {
    // By having each module responsible for setting up its own routing,
    // it makes the root module a lot cleaner.
    Router::new()
        .route("/api/users", post(create_user))
        .route("/api/users/login", post(login_user))
        .route("/api/user", get(get_current_user).put(update_user))
}

/// A wrapper type for all requests/responses from these routes.
#[derive(serde::Serialize, serde::Deserialize)]
struct UserBody<T> {
    user: T,
}

#[derive(serde::Deserialize)]
struct NewUser {
    username: String,
    email: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct LoginUser {
    email: String,
    password: String,
}

#[derive(serde::Deserialize, Default, PartialEq, Eq)]
#[serde(default)] // fill in any missing fields with `..UpdateUser::default()`
struct UpdateUser {
    email: Option<String>,
    username: Option<String>,
    password: Option<String>,
    bio: Option<String>,
    image: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct User {
    email: String,
    token: String,
    username: String,
    bio: String,
    image: Option<String>,
}

// https://realworld-docs.netlify.app/docs/specs/backend-specs/endpoints#registration
async fn create_user(
    ctx: State<ApiContext>,
    cookies: Cookies,
    Json(req): Json<UserBody<NewUser>>,
) -> Result<Json<UserBody<User>>> {
    let password_hash = hash_password(req.user.password).await?;

    // I personally prefer using queries inline in request handlers as it's easier to understand the
    // query's semantics in the wider context of where it's invoked.
    //
    // Sometimes queries just get too darn big, though. In that case it may be a good idea
    // to move the query to a separate module.
    let user_id = sqlx::query_scalar!(
        // language=PostgreSQL
        r#"insert into "user" (username, email, password_hash) values ($1, $2, $3) returning user_id"#,
        req.user.username,
        req.user.email,
        password_hash
    )
    .fetch_one(&ctx.db)
    .await
    .on_constraint("user_username_key", |_| {
        Error::unprocessable_entity([("username", "username taken")])
    })
    .on_constraint("user_email_key", |_| {
        Error::unprocessable_entity([("email", "email taken")])
    })?;

    // we need to create a access token and refresh token for the user
    let access_token = AuthUser { user_id }.to_jwt(&ctx);
    let refresh_token = AuthUser { user_id }.to_jwt_and_kv_store(&ctx)?;

    cookies.add(Cookie::new("refresh_token", refresh_token));

    // we need to store the refresh token in the kv store
    // store the key as email and the values as an array of refresh tokens
    // for this we need to get the values first and then append the new refresh token

    Ok(Json(UserBody {
        user: User {
            email: req.user.email,
            token: access_token,
            username: req.user.username,
            bio: "".to_string(),
            image: None,
        },
    }))
}

// https://realworld-docs.netlify.app/docs/specs/backend-specs/endpoints#authentication
async fn login_user(
    ctx: State<ApiContext>,
    cookies: Cookies,
    Json(req): Json<UserBody<LoginUser>>,
) -> Result<Json<UserBody<User>>> {
    let user = sqlx::query!(
        r#"
            select user_id, email, username, bio, image, password_hash 
            from "user" where email = $1
        "#,
        req.user.email,
    )
    .fetch_optional(&ctx.db)
    .await?
    .ok_or_else(|| Error::unprocessable_entity([("email", "does not exist")]))?;

    verify_password(req.user.password, user.password_hash).await?;

    let user_id = user.user_id;

    let access_token = AuthUser { user_id }.to_jwt(&ctx);
    let refresh_token = AuthUser { user_id }.to_jwt_and_kv_store(&ctx)?;

    // send the refresh token as a cookie
    cookies.add(Cookie::new("refresh_token", refresh_token));

    Ok(Json(UserBody {
        user: User {
            email: user.email,
            token: access_token,
            username: user.username,
            bio: user.bio,
            image: user.image,
        },
    }))
}

async fn refresh(
    auth_user: AuthUser,
    ctx: State<ApiContext>,
    cookies: Cookies,
) -> Result<Json<UserBody<User>>> {
    let user_id = auth_user.user_id;
    let user = sqlx::query!(
        r#"
            select user_id, email, username, bio, image, password_hash 
            from "user" where user_id = $1
        "#,
        user_id,
    )
    .fetch_optional(&ctx.db)
    .await?
    .ok_or_else(|| Error::unprocessable_entity([("email", "does not exist")]))?;

    // get token from cookie
    let token = cookies
        .get("refresh_token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let user_id = user.user_id;

    let new_refresh_token = AuthUser { user_id }.refresh(&ctx, &token)?;

    cookies.remove(Cookie::named("refresh_token"));
    cookies.add(Cookie::new("refresh_token", new_refresh_token));

    let auth_token = AuthUser { user_id }.to_jwt(&ctx);

    Ok(Json(UserBody {
        user: User {
            email: user.email,
            token: auth_token,
            username: user.username,
            bio: user.bio,
            image: user.image,
        },
    }))
}

// https://realworld-docs.netlify.app/docs/specs/backend-specs/endpoints#get-current-user
async fn get_current_user(
    auth_user: AuthUser,
    ctx: State<ApiContext>,
) -> Result<Json<UserBody<User>>> {
    let user = sqlx::query!(
        r#"select email, username, bio, image from "user" where user_id = $1"#,
        auth_user.user_id
    )
    .fetch_one(&ctx.db)
    .await?;

    Ok(Json(UserBody {
        user: User {
            email: user.email,
            // The spec doesn't state whether we're supposed to return the same token we were passed,
            // or generate a new one. Generating a new one is easier the way the code is structured.
            //
            // This has the side-effect of automatically refreshing the session if the frontend
            // updates its token based on this response.
            token: auth_user.to_jwt(&ctx),
            username: user.username,
            bio: user.bio,
            image: user.image,
        },
    }))
}

// https://realworld-docs.netlify.app/docs/specs/backend-specs/endpoints#update-user
// Semantically, because this route allows a partial update it should be `PATCH`, not `PUT`.
// However, we have a spec to follow so `PUT` it is.
async fn update_user(
    auth_user: AuthUser,
    ctx: State<ApiContext>,
    Json(req): Json<UserBody<UpdateUser>>,
) -> Result<Json<UserBody<User>>> {
    if req.user == UpdateUser::default() {
        // If there's no fields to update, these two routes are effectively identical.
        return get_current_user(auth_user, ctx).await;
    }

    // WTB `Option::map_async()`
    let password_hash = if let Some(password) = req.user.password {
        Some(hash_password(password).await?)
    } else {
        None
    };

    let user = sqlx::query!(
        // This is how we do optional updates of fields without needing a separate query for each.
        // language=PostgreSQL
        r#"
            update "user"
            set email = coalesce($1, "user".email),
                username = coalesce($2, "user".username),
                password_hash = coalesce($3, "user".password_hash),
                bio = coalesce($4, "user".bio),
                image = coalesce($5, "user".image)
            where user_id = $6
            returning email, username, bio, image
        "#,
        req.user.email,
        req.user.username,
        password_hash,
        req.user.bio,
        req.user.image,
        auth_user.user_id
    )
    .fetch_one(&ctx.db)
    .await
    .on_constraint("user_username_key", |_| {
        Error::unprocessable_entity([("username", "username taken")])
    })
    .on_constraint("user_email_key", |_| {
        Error::unprocessable_entity([("email", "email taken")])
    })?;

    Ok(Json(UserBody {
        user: User {
            email: user.email,
            token: auth_user.to_jwt(&ctx),
            username: user.username,
            bio: user.bio,
            image: user.image,
        },
    }))
}

async fn hash_password(password: String) -> Result<String> {
    // Argon2 hashing is designed to be computationally intensive,
    // so we need to do this on a blocking thread.
    tokio::task::spawn_blocking(move || -> Result<String> {
        let salt = SaltString::generate(rand::thread_rng());
        Ok(
            PasswordHash::generate(Argon2::default(), password, salt.as_salt())
                .map_err(|e| anyhow::anyhow!("failed to generate password hash: {}", e))?
                .to_string(),
        )
    })
    .await
    .context("panic in generating password hash")?
}

async fn verify_password(password: String, password_hash: String) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let hash = PasswordHash::new(&password_hash)
            .map_err(|e| anyhow::anyhow!("invalid password hash: {}", e))?;

        hash.verify_password(&[&Argon2::default()], password)
            .map_err(|e| match e {
                argon2::password_hash::Error::Password => Error::Unauthorized,
                _ => anyhow::anyhow!("failed to verify password hash: {}", e).into(),
            })
    })
    .await
    .context("panic in verifying password hash")?
}
