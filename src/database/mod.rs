pub mod connect_to_db;
pub mod impl_mondo_db;

use crate::models::tokens::Token;
use crate::models::response::login_response::LoginResponse;

pub enum LoginError {
    Ok(LoginResponse),
    WrongLogin,
    WrongPassword,
    NotPermit,
    Unknown,
}

pub enum RegistrationError {
    Ok(Token),
    AlreadyRegisteredByEmail,
    AlreadyRegisteredByLogin,
    AlreadyRegisteredByUsername,
    WrongPassword,
    Unknown,
}

pub enum FeederError {
    Ok(String),
    AlreadyRegisteredByEmail,
    AlreadyRegisteredByUsername
}

pub enum FindUserBy {
    UserNotFound,
    UserFoundByLogin,
    UserFoundByEmail,
    UserFoundByUsername,
}

pub enum  AllowError {
    Ok(),
    UserNotFound,
}
