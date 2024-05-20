use serde::{Deserialize,Serialize};
use crate::models::tokens::Token;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginResponse {
    pub token : Token,
    pub userID : String,
    pub role : i32,
}
