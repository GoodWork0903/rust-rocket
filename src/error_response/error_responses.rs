use crate::Status;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub(crate) cause: &'static str,
}

// common errors
pub const ERROR_UNKNOWN_STATUS: Status = Status::InternalServerError;
pub const UNKNOWN_JSON: ErrorResponse = ErrorResponse {
    cause: "Internal Server Error",
};

pub const ERROR_WRONG_REQUEST_STATUS: Status = Status::BadRequest;
pub const WRONG_REQUEST_JSON: ErrorResponse = ErrorResponse {
    cause: "Wrong request",
};

pub const ERROR_UNAUTHORIZED_STATUS: Status = Status::Unauthorized;
pub const UNAUTHORIZED_JSON: ErrorResponse = ErrorResponse {
    cause: "Unauthorized",
};

// login error
pub const ERROR_USER_NOT_FOUND_STATUS: Status = Status::BadRequest;
pub const USER_NOT_FOUND_JSON: ErrorResponse = ErrorResponse {
    cause: "User not found",
};

pub const LOGIN_NOT_PERMIT_JSON: ErrorResponse = ErrorResponse {
    cause: "Login not permit",
};

pub const PASSWORD_NOT_CORRECT: ErrorResponse = ErrorResponse {
    cause: "Password not correct",
};

pub const USERNAME_NOT_REGISTER_JSON: ErrorResponse = ErrorResponse {
    cause: "User not registered",
};

pub const PASSWORD_NOT_CORRECT_JSON: ErrorResponse = ErrorResponse {
    cause: "Password not correct",
};

// registration error
pub const ERROR_WEAK_PASSWORD_STATUS: Status = Status::BadRequest;
pub const WEAK_PASSWORD_JSON: ErrorResponse = ErrorResponse {
    cause: "Weak password",
};

pub const ERROR_WEAK_LOGIN_STATUS: Status = Status::BadRequest;
pub const WEAK_LOGIN_JSON: ErrorResponse = ErrorResponse {
    cause: "Weak login",
};

pub const ERROR_WRONG_MAIL_STATUS: Status = Status::BadRequest;
pub const WRONG_MAIL_JSON: ErrorResponse = ErrorResponse {
    cause: "Wrong mail",
};

pub const ERROR_ALREADY_REGISTERED_STATUS: Status = Status::BadRequest;
pub const ALREADY_REGISTERED_LOGIN_JSON: ErrorResponse = ErrorResponse {
    cause: "Already registered by login",
};
pub const ALREADY_REGISTERED_EMAIL_JSON: ErrorResponse = ErrorResponse {
    cause: "Already registered by email",
};

pub const ALREADY_REGISTERED_USER_JSON: ErrorResponse = ErrorResponse {
    cause: "Already registered by username",
};

pub const ERROR_WRONG_FIRST_NAME_STATUS: Status = Status::BadRequest;
pub const WRONG_FIRST_NAME_JSON: ErrorResponse = ErrorResponse {
    cause: "Wrong first name",
};

pub const ERROR_WRONG_LAST_NAME_STATUS: Status = Status::BadRequest;
pub const WRONG_LAST_NAME_JSON: ErrorResponse = ErrorResponse {
    cause: "Wrong last name",
};

pub const ERROR_NOT_FOUND_STATUS: Status = Status::NotFound;
pub const NOT_FOUND_JSON: ErrorResponse = ErrorResponse { cause: "Not found" };


//user error 
pub const USER_NOT_PERMINT_JSON: ErrorResponse = ErrorResponse {
    cause: "You are not permit for this action",
};