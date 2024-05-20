#[macro_use]
extern crate rocket;
use rocket::fs::FileName;
use rocket::http::Method;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket_contrib::serve::StaticFiles;
use crate::database::connect_to_db::init;
use crate::error_response::error_responses::{
    ErrorResponse, NOT_FOUND_JSON, UNAUTHORIZED_JSON, UNKNOWN_JSON,
};
use rocket::{fs::NamedFile, response::Redirect};
use std::path::{Path, PathBuf};
use std::fs;
use crate::helper::check_valid_text;
use crate::routes::authorization::login::login;
use crate::routes::authorization::registration::registration;
use crate::routes::routes::users::{
    admin_user_create, delete_user, feeder, forget_password, get_userinfo, get_userlist,
    user_allow, user_change,
};
pub mod constants;
mod database;
pub mod error_response;
mod helper;
mod models;
mod private;
mod routes;
use rocket_cors::{
    AllowedHeaders,
    AllowedOrigins,
    CorsOptions,     
};

#[get("/<file..>")]
async fn files(file: PathBuf) -> Option<NamedFile> {
    
    NamedFile::open(Path::new("src/static/").join(file)).await.ok()
}

#[get("/<file..>")]
async fn ft(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("src/templates/").join(file)).await.ok()
}
// #[get("/")]
// async fn first () -> Option<NamedFile>{
//     let file_path = Path::new("src/templates/auth/login.html");
//     match fs::metadata(&file_path) {
//         Ok(metadata) => {
//             if metadata.is_file() {
//                 println!("File exists: {}", file_path.display());
//             } else {
//                 println!("Path exists, but it is not a file: {}", file_path.display());
//             }
//         }
//         Err(_) => println!("File does not exist: {}", file_path.display()),
//     }

//     NamedFile::open(Path::new("src/templates/auth/login.html")).await.ok()
// }

#[get("/")]
async fn first() -> Option<NamedFile> {
    let file_path = Path::new("src/templates/auth/login.html");
    
    // Check if the file exists
    if file_path.exists() {
        // Try to open the file asynchronously
        if let Ok(file) = NamedFile::open(file_path).await {
            return Some(file);
        } else {
            // Failed to open the file
            println!("Failed to open file: {}", file_path.display());
        }
    } else {
        // File does not exist
        println!("File does not exist: {}", file_path.display());
    }

    // Return None if file does not exist or failed to open
    None
}

#[launch]
async fn rocket() -> _{

    // Cors Option 
    let cors = CorsOptions {
        allowed_origins: AllowedOrigins::all(),
        allowed_methods: vec![Method::Get, Method::Post, Method::Put, Method::Delete]
            .into_iter()
            .map(From::from)
            .collect(),
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .expect("Error while building CORS");

    // Main

    rocket::build()
        .attach(init().await)
        .attach(cors)
        .mount("/static", routes![files])
        .mount("/api/v0/TSP/auth", routes![registration, login])
        // Usermanagement router
        .mount("/api/v0/TSP/feeder", routes![feeder])
        .mount(
            "/api/v0/TSP/usermanager",
            routes![
                admin_user_create,
                user_allow,
                user_change,
                forget_password,
                get_userlist,
                get_userinfo,
                delete_user,
            ],
        )
        .mount("/ft", routes![ft])
        .mount("/", routes![first])
        .register(
            "/",
            catchers![unauthorized, not_found, internal_sever_error,],
        )
}

/**
 * Error handler
 */
#[catch(401)]
pub fn unauthorized() -> Json<ErrorResponse> {
    Json(UNAUTHORIZED_JSON)
}

/**
 * Error handler
 */
#[catch(404)]
pub fn not_found() -> Json<ErrorResponse> {
    Json(NOT_FOUND_JSON)
}

/**
 * Error handler
 */
#[catch(500)]
pub fn internal_sever_error() -> Json<ErrorResponse> {
    Json(UNKNOWN_JSON)
}
