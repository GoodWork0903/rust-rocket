use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ForgetPasswordRequest {
    pub email: String,
    pub otp : String,
    pub new_password: String,
}
