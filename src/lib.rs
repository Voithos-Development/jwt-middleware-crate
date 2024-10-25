use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use jwt_simple::prelude::*;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    sub: String,
    exp: u64,
}

pub async fn jwt_middleware(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, Error> {
    let token = credentials.token();
    let secret = env::var("SUPABASE_JWT_SECRET").expect("JWT secret not set");

    // Create the key for HS256 algorithm
    let key = HS256Key::from_bytes(secret.as_bytes());

    // Verify the token and extract claims
    let claims = key
        .verify_token::<CustomClaims>(token, None)
        .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid JWT"))?;

    // Insert the claims into the request context
    req.extensions_mut().insert(claims.custom);
    Ok(req)
}
