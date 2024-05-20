use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use crate::models::response::login_response::LoginResponse;
use crate::constants::{
    LEN_LOGIN, LEN_PASSWORD, LOGIN_NOT_PERMIT, PASSWORD_NOT_CORRECT, USERNAME_NOT_REGISTER,
    WRONG_REQUEST,
};
use crate::database::connect_to_db::MongoDB;
use crate::database::LoginError;
use crate::error_response::error_responses::ErrorResponse;
use crate::models::request::login_request::LoginRequest;
use crate::models::tokens::{Token};
use crate::routes::authorization::LoginRequestError;
use crate::routes::validator_authorization::get_valid_username_and_password;
use crate::routes::TypeValidTwoStr;

/**
 * Login using this API
 * Request {option_login_request : LoginRequest}
 * Response {LoginResponse}
 */
#[post("/login", format = "json", data = "<option_login_request>")]
pub async fn login(
    database: &State<MongoDB>,
    option_login_request: Option<Json<LoginRequest>>,
) -> Result<Json<LoginResponse>, (Status, Json<ErrorResponse>)> {
    match check_login_request(option_login_request) {
        LoginRequestError::Ok(login_request) => match login_match(database, login_request).await {
            Ok(res) => Ok(Json(res)),
            Err(err) => match err {
                LoginError::NotPermit => Err(LOGIN_NOT_PERMIT),
                LoginError::WrongLogin => Err(USERNAME_NOT_REGISTER),
                LoginError::WrongPassword => Err(PASSWORD_NOT_CORRECT),
                _ => Err(WRONG_REQUEST),
            }, 
        },
        LoginRequestError::NoneLoginRequest => Err(WRONG_REQUEST),
        LoginRequestError::BadLogin => Err(WRONG_REQUEST),
        LoginRequestError::BadPassword => Err(WRONG_REQUEST),
    }
}

/**
 * to check validation  login information
 * parameter {option_login_request: LoginRequest}
 * return : LoginRequestError
 */
fn check_login_request(option_login_request: Option<Json<LoginRequest>>) -> LoginRequestError {
    match option_login_request {
        None => LoginRequestError::NoneLoginRequest,
        Some(login_request) => {
            match get_valid_username_and_password(
                &login_request.email,
                &login_request.password,
                LEN_LOGIN,
                LEN_PASSWORD,
            ) {
                TypeValidTwoStr::Ok => LoginRequestError::Ok(login_request),
                TypeValidTwoStr::BadFirst => LoginRequestError::BadLogin,
                TypeValidTwoStr::BadSecond => LoginRequestError::BadPassword,
            }
        }
    }
}

/**
 * to check validation  login information
 * parameters {login_request : LoginRequest, database : MongoDB connection}
 * return : LoginResponse
 * 
 */
async fn login_match(
    database: &State<MongoDB>,
    login_request: Json<LoginRequest>,
) -> Result<LoginResponse, LoginError> {
    match database.login(login_request).await {
        Ok(LoginError::Ok(res)) => Ok(res),
        Ok(LoginError::NotPermit) => Err(LoginError::NotPermit), // Directly return Err(LoginError::NotPermit)
        Ok(LoginError::WrongPassword) => Err(LoginError::WrongPassword),
        Ok(LoginError::WrongLogin) => Err(LoginError::WrongLogin),
        Ok(LoginError::Unknown) => Err(LoginError::Unknown),
        Err(_) => Err(LoginError::Unknown),
    }
}
