use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct UserChangeRequest {
    pub username: String,
    pub password: String,
    pub email : String,
    pub first_name : String,
    pub last_name : String,
    pub role : i32,
    pub allow : bool
}
