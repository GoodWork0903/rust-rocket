use crate::models::request::patch_request::EditUserRequest;
use rocket::serde::json::Json;

pub mod users;

pub enum EditUserRequestError {
    Ok(Json<EditUserRequest>),
    NoneEditModel,
    BadMail,
    BadLogin,
    BadFirstName,
    BadLastName,
}
