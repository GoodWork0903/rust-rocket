use rocket::serde::json::Json;
use rocket::time::format_description::modifier::Second;
use rocket::State;

use crate::constants::{
    ALREADY_REGISTERED_LOGIN, ALREADY_REGISTERED_MAIL, UNKNOWN, USER_NOT_PERMINT, WEAK_LOGIN,
    WEAK_PASSWORD, WRONG_FIRST_NAME, ALREADY_REGISTERED_USER, WRONG_MAIL, WRONG_REQUEST,
};
use crate::database::connect_to_db::MongoDB;
use crate::database::{self, AllowError, FeederError, RegistrationError};
use crate::models::model_user::User;
use crate::models::request::forget_password::ForgetPasswordRequest;
use crate::models::request::registration_request::RegistrationRequest;
use crate::models::request::user_change_request::UserChangeRequest;
use crate::routes::authorization::registration::check_registration_request;
use crate::routes::authorization::token::request_access_token::AuthorizedUser;
use crate::routes::authorization::RegistrationRequestError;
use crate::{ErrorResponse, Status};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Success {
    pub message: String,
}

/**
 * Admin create new user Using this API
 * Request {option_registration_request : RegistrationRequest}
 * Response {data : Success}
 */
#[post("/createuser", format = "json", data = "<option_registration_request>")]
pub async fn admin_user_create(
    auth: AuthorizedUser,
    option_registration_request: Option<Json<RegistrationRequest>>,
    database: &State<MongoDB>,
) -> Result<Json<Success>, (Status, Json<ErrorResponse>)> {
    if auth.user_role != 0 && auth.user_role != 1 && auth.user_role != 2 {
        Err(USER_NOT_PERMINT)
    } else {
        match check_registration_request(option_registration_request) {
            RegistrationRequestError::Ok(registration_request) => {
                match database.admin_user_registration(registration_request).await {
                    Ok(RegistrationError::Ok(token)) => Ok(Json(Success {
                        message: "Success".to_string(),
                    })),
                    Ok(RegistrationError::AlreadyRegisteredByEmail) => Err(ALREADY_REGISTERED_MAIL),
                    Ok(RegistrationError::AlreadyRegisteredByLogin) => {
                        Err(ALREADY_REGISTERED_LOGIN)
                    }
                    Ok(RegistrationError::WrongPassword) => Err(WEAK_PASSWORD),
                    Ok(RegistrationError::Unknown) => Err(UNKNOWN),
                    Ok(RegistrationError::AlreadyRegisteredByUsername) => Err(ALREADY_REGISTERED_USER),
                    Err(_) => Err(UNKNOWN),
                }
            }
            RegistrationRequestError::NoneRegistrationRequest => Err(WRONG_REQUEST),
            RegistrationRequestError::BadLogin => Err(WEAK_LOGIN),
            RegistrationRequestError::BadPassword => Err(WEAK_PASSWORD),
            RegistrationRequestError::BadMail => Err(WRONG_MAIL),
        }
    }
}

/**
 * Get all of user Using this API
 * Response {data : Vec<User>}
 */
#[get("/userlist")]
pub async fn get_userlist(
    auth: AuthorizedUser,
    database: &State<MongoDB>,
) -> Result<Json<Vec<User>>, (Status, Json<ErrorResponse>)> {
    match database.getUserList().await {
        Ok(res) => Ok(Json(res)),
        Err(_) => Err(UNKNOWN),
    }
}

/**
 * Get all of user Using this API
 * parameter {id : string}
 * Response {data : User}
 */
#[get("/user/<id>")]
pub async fn get_userinfo(
    auth: AuthorizedUser,
    id: String,
    database: &State<MongoDB>,
) -> Result<Json<User>, (Status, Json<ErrorResponse>)> {
    match database.get_userinfo(id).await {
        Ok(res) => match res {
            Some(response) => Ok(Json(response)),
            None => Err(WRONG_REQUEST),
        },
        Err(_) => Err(WRONG_REQUEST),
    }
}

/**
 * delete user Using this API
 * parameter {id : string}
 * Response  {data : Success}
 */
#[delete("/delete/<id>")]
pub async fn delete_user(
    auth: AuthorizedUser,
    id: String,
    database: &State<MongoDB>,
) -> Result<Json<Success>, (Status, Json<ErrorResponse>)> {
    match database.delete_user(id).await {
        Ok(_) => Ok(Json(Success {
            message: "Success".to_string(),
        })),
        Err(_) => Err(WRONG_REQUEST),
    }
}

/**
 * allow user can login Using this API
 * parameter {id : string}
 * Response {data : Success}
 */
#[put("/user_allow/<id>")]
pub async fn user_allow(
    auth: AuthorizedUser,
    id: String,
    database: &State<MongoDB>,
) -> Result<Json<Success>, (Status, Json<ErrorResponse>)> {
    if auth.user_role != 0 && auth.user_role != 1 && auth.user_role != 2 {
        Err(USER_NOT_PERMINT)
    } else {
        if id.is_empty() {
            Err(WRONG_REQUEST)
        } else {
            match database.allow_user(id).await {
                Ok(AllowError::Ok()) => Ok(Json(Success {
                    message: "success".to_string(),
                })),
                Ok(AllowError::UserNotFound) => Err(WRONG_REQUEST),
                Err(_) => Err(UNKNOWN),
            }
        }
    }
}

/**
 * reset password can login Using this API
 * parameter {id : string}
 * Request {data_body : ForgetPasswordRequest }
 * Response  {data : Success}
 */
#[put("/forget_password", format = "json", data = "<data_body>")]
pub async fn forget_password(
    data_body: Option<Json<ForgetPasswordRequest>>,
    database: &State<MongoDB>,
) -> Result<Json<Success>, (Status, Json<ErrorResponse>)> {
    match data_body {
        None => Err(UNKNOWN),
        Some(user_info) => {
            let auth = user_info.into_inner();
            if auth.new_password.to_string().len() < 5{
                Err(WEAK_PASSWORD)
            } else {
                match database
                    .forget_password(auth.email, auth.new_password)
                    .await
                {
                    Ok(AllowError::Ok()) => Ok(Json(Success {
                        message: "success".to_string(),
                    })),
                    Ok(AllowError::UserNotFound) => Err(WRONG_REQUEST),
                    Err(_) => Err(UNKNOWN),
                }
            }
        }
    }
}

/**
 * user infomation updated Using this API
 * parameter {id : string}
 * Request {userinfo_request : UserChangeRequest}
 * Response {data : Success}
 */
#[put("/user_change/<id>", format = "json", data = "<userinfo_request>")]
pub async fn user_change(
    auth: AuthorizedUser,
    id: String,
    userinfo_request: Option<Json<UserChangeRequest>>,
    database: &State<MongoDB>,
) -> Result<Json<Success>, (Status, Json<ErrorResponse>)> {
    println!("{}", id);
    if auth.user_role != 0 && auth.user_role != 1 && auth.user_role != 2 {
        Err(USER_NOT_PERMINT)
    } else {
        if id.is_empty() {
            Err(WRONG_REQUEST)
        } else {
            match database.change_user(id, userinfo_request).await {
                Ok(AllowError::Ok()) => Ok(Json(Success {
                    message: "success".to_string(),
                })),
                Ok(AllowError::UserNotFound) => Err(WRONG_REQUEST),
                Err(_) => Err(UNKNOWN),
            }
        }
    }
}

/**
 * SuperAdmin created Using this API
 * parameter {id : string}
 * Response {data : Success}
 */
#[get("/feeder")]
pub async fn feeder(database: &State<MongoDB>) -> Result<Json<Success>,(Status, Json<ErrorResponse>) > {
    match database.feeder().await {
        Ok(FeederError::Ok(res)) => Ok(Json(Success { message: res })),
        Ok(FeederError::AlreadyRegisteredByEmail) => Ok(Json(Success {
            message: "User already registered".to_string(),
        })),
        Ok(FeederError::AlreadyRegisteredByUsername) => Ok(Json(Success {
            message: "User already registered".to_string(),
        })),
        Err(_) => Err(WRONG_REQUEST)
    }
}
