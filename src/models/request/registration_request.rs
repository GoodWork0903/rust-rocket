use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    pub email : String,
    pub username: String, 
    pub first_name : String,
    pub last_name : String,
    pub password: String,
    pub role: i32,
}
