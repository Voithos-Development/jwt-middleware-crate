use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomClaims {
    pub sub: String,
    pub exp: u64,
}

pub async fn jwt_middleware(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let token = credentials.token();
    let secret = env::var("SUPABASE_JWT_SECRET").expect("JWT secret not set");

    // Create the key for HS256 algorithm
    let key = HS256Key::from_bytes(secret.as_bytes());

    // Verify the token and extract claims
    match key.verify_token::<CustomClaims>(token, None) {
        Ok(claims) => {
            // Insert the claims into the request context
            req.extensions_mut().insert(claims.custom);
            Ok(req)
        }
        Err(_) => Err((actix_web::error::ErrorUnauthorized("Invalid JWT"), req)),
    }
}
