use serde::{Deserialize,Serialize};
use crate::models::tokens::Token;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserListResponse {
    pub email : String,
    pub username: String, 
    pub first_name : String,
    pub last_name : String,
    pub password: String,
    pub role: i32,
    pub allow : bool
}
