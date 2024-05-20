use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]

pub struct User {
    pub _id: ObjectId,
    pub email : String,
    pub username : String,
    pub first_name: String,
    pub last_name: String,
    pub role: i32,
    pub password: String,
    pub allow : bool
}
