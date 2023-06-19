use crate::http::error::Error;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;

use crate::http::ApiContext;
use async_trait::async_trait;
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderValue;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use redis::Commands;
use sha2::Sha384;
use time::OffsetDateTime;
use uuid::Uuid;

const DEFAULT_SESSION_LENGTH: time::Duration = time::Duration::weeks(2);

// Ideally the Realworld spec would use the `Bearer` scheme as that's relatively standard
// and has parsers available, but it's really not that hard to parse anyway.
const SCHEME_PREFIX: &str = "Token ";

/// Add this as a parameter to a handler function to require the user to be logged in.
///
/// Parses a JWT from the `Authorization: Token <token>` header.
pub struct AuthUser {
    pub user_id: Uuid,
}

/// Add this as a parameter to a handler function to optionally check if the user is logged in.
///
/// If the `Authorization` header is absent then this will be `Self(None)`, otherwise it will
/// validate the token.
///
/// This is in contrast to directly using `Option<AuthUser>`, which will be `None` if there
/// is *any* error in deserializing, which isn't exactly what we want.
pub struct MaybeAuthUser(pub Option<AuthUser>);

#[derive(serde::Serialize, serde::Deserialize)]
struct AuthUserClaims {
    user_id: Uuid,
    /// Standard JWT `exp` claim.
    exp: i64,
}

impl AuthUser {
    fn invalidate_jwt(ctx: &ApiContext, user_id: &String, token: &String) -> anyhow::Result<()> {
        let mut kv_store = ctx.kv_store.lock().unwrap();

        let mut tokens: Vec<String> = kv_store.get(user_id).unwrap_or_else(|_| vec![]);

        // remove old token
        tokens.retain(|t| t != token);

        // removed expired tokens
        tokens.retain(|t| {
            let jwt = jwt::Token::<jwt::Header, AuthUserClaims, _>::parse_unverified(t).unwrap();

            let (_header, claims) = jwt.into();

            let exp = claims.exp;

            let now = OffsetDateTime::now_utc().unix_timestamp();

            exp > now
        });

        kv_store.set(user_id, tokens)?;

        Ok(())
    }

    fn verify_jwt_token(ctx: &ApiContext, token: &str) -> Result<AuthUserClaims, Error> {
        let jwt =
            jwt::Token::<jwt::Header, AuthUserClaims, _>::parse_unverified(token).map_err(|e| {
                log::debug!("failed to parse token {}", e);
                Error::Unauthorized
            })?;

        let hmac = Hmac::<Sha384>::new_from_slice(ctx.config.hmac_key.as_bytes())
            .expect("HMAC-SHA-384 can accept any key length");

        let jwt = jwt.verify_with_key(&hmac).map_err(|e| {
            log::debug!("JWT failed to verify: {}", e);
            Error::Unauthorized
        })?;

        let (_header, claims) = jwt.into();
        Ok(claims)
    }

    pub(in crate::http) fn to_jwt(&self, ctx: &ApiContext) -> String {
        let hmac = Hmac::<Sha384>::new_from_slice(ctx.config.hmac_key.as_bytes())
            .expect("HMAC-SHA-384 can accept any key length");

        AuthUserClaims {
            user_id: self.user_id,
            exp: (OffsetDateTime::now_utc() + DEFAULT_SESSION_LENGTH).unix_timestamp(),
        }
        .sign_with_key(&hmac)
        .expect("HMAC signing should be infallible")
    }

    // do to_jwt_refresh_token where we store the refresh token in redis
    pub(in crate::http) fn to_jwt_and_kv_store(&self, ctx: &ApiContext) -> anyhow::Result<String> {
        let hmac = Hmac::<Sha384>::new_from_slice(ctx.config.hmac_key.as_bytes())
            .expect("HMAC-SHA-384 can accept any key length");

        let token = AuthUserClaims {
            user_id: self.user_id,
            exp: (OffsetDateTime::now_utc() + DEFAULT_SESSION_LENGTH).unix_timestamp(),
        }
        .sign_with_key(&hmac)
        .expect("HMAC signing should be infallible");

        AuthUser::invalidate_jwt(ctx, &self.user_id.to_string(), &token)?;

        Ok(token)
    }

    pub(in crate::http) fn refresh(&self, ctx: &ApiContext, token: &String) -> Result<String, Error> {
        let claims = AuthUser::verify_jwt_token(ctx, token)?;

        let exp = claims.exp;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if exp < now {
            log::debug!("JWT has expired");
            return Err(Error::Unauthorized);
        }

        AuthUser::invalidate_jwt(ctx, &claims.user_id.to_string(), &token.to_string())?;
        let new_token = self.to_jwt_and_kv_store(ctx)?;
        Ok(new_token)
    }

    fn from_authorization(ctx: &ApiContext, auth_header: &HeaderValue) -> Result<Self, Error> {
        let auth_header = auth_header.to_str().map_err(|_| {
            log::debug!("Authorization header is not UTF-8");
            Error::Unauthorized
        })?;
        if !auth_header.starts_with(SCHEME_PREFIX) {
            log::debug!(
                "Authorization header is using the wrong scheme: {:?}",
                auth_header
            );
            return Err(Error::Unauthorized);
        }
        let token = &auth_header[SCHEME_PREFIX.len()..];
        let claims = AuthUser::verify_jwt_token(ctx, token)?;

        if claims.exp < OffsetDateTime::now_utc().unix_timestamp() {
            log::debug!("token expired");
            return Err(Error::Unauthorized);
        }

        Ok(AuthUser {
            user_id: claims.user_id,
        })
    }
}

impl MaybeAuthUser {
    /// If this is `Self(Some(AuthUser))`, return `AuthUser::user_id`
    pub fn user_id(&self) -> Option<Uuid> {
        self.0.as_ref().map(|auth_user| auth_user.user_id)
    }
}

// tower-http has a `RequireAuthorizationLayer` but it's useless for practical applications,
// as it only supports matching Basic or Bearer auth with credentials you provide it.
//
// There's the `::custom()` constructor to provide your own validator but it basically
// requires parsing the `Authorization` header by-hand anyway so you really don't get anything
// out of it that you couldn't write your own middleware for, except with a bunch of extra
// boilerplate.
#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    ApiContext: FromRef<S>,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ctx: ApiContext = ApiContext::from_ref(state);

        // Get the value of the `Authorization` header, if it was sent at all.
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(Error::Unauthorized)?;

        Self::from_authorization(&ctx, auth_header)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for MaybeAuthUser
where
    S: Send + Sync,
    ApiContext: FromRef<S>,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ctx: ApiContext = ApiContext::from_ref(state);

        Ok(Self(
            // Get the value of the `Authorization` header, if it was sent at all.
            parts
                .headers
                .get(AUTHORIZATION)
                .map(|auth_header| AuthUser::from_authorization(&ctx, auth_header))
                .transpose()?,
        ))
    }
}
