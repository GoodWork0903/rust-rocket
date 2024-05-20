use crate::models::tokens::Token;
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

pub enum EncodeJwtHelper {
    Ok(String),
    Err,
}

pub enum DecodeJwtHelper {
    Ok(TokenData<Claims>),
    Err,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: String,
    pub role : i32,
    pub exp: usize,
}

/**
 * Encoded JWT tocken
 * parameters {id : ObjectId, role : i32, secret : str, expiration : i64}
 * reutrn : EncodeJwtHelper
 */
pub fn encode_jwt(id: ObjectId, role : i32, secret: &'static str, expiration: i64) -> EncodeJwtHelper {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(expiration))
        .expect("valid timestamp")
        .timestamp();

    let my_claims = Claims {
        user_id: id.to_string(),
        role : role,
        exp: expiration as usize,
    };
    match encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ) {
        Ok(token) => EncodeJwtHelper::Ok(token),
        Err(_) => EncodeJwtHelper::Err,
    }
}

/**
 * Decoded JWT tocken
 * parameters {token : String}
 * return :  DecodeJwtHelper
 */
pub fn decode_jwt(token: String, secret: &'static str) -> DecodeJwtHelper {
    let token = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    );
    match token {
        Ok(token_string) => DecodeJwtHelper::Ok(token_string),
        Err(_) => DecodeJwtHelper::Err,
    }
}

/**
 * Create JWT tocken
 * parameters {id : ObjectId, role : i32, jwt_secret : &str, expiration_token : i64} 
 * return : Token
 */
pub fn encode_token_and_refresh(
        id: ObjectId,
        role : i32,
        jwt_secret: &'static str,
        refresh_token_secret: &'static str,
        expiration_refresh_token: i64,
        expiration_token: i64,
    ) -> Result<Token, ()> {
        match encode_jwt(id,role, jwt_secret, expiration_token) {
            EncodeJwtHelper::Ok(token) => Ok(Token {
                token,
            }),
            EncodeJwtHelper::Err => Err(()),
        }
    }
    