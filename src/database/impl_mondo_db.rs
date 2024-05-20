use crate::constants::{EXPIRATION_REFRESH_TOKEN, EXPIRATION_TOKEN};
use crate::database::connect_to_db::MongoDB;
use crate::database::{AllowError, FeederError, FindUserBy, LoginError, RegistrationError};
use crate::helper::{find_user_by_email_username, hash_text};
use crate::models::model_user::User;
use crate::models::request::login_request::LoginRequest;
use crate::models::request::registration_request::RegistrationRequest;
use crate::models::request::user_change_request::UserChangeRequest;
use crate::models::response::login_response::LoginResponse;
use crate::models::response::userlist_response::UserListResponse;
use crate::private::{
    ADMIN_EMAIL, ADMIN_FIRST_NAME, ADMIN_LAST_NAME, ADMIN_PASSWORD, ADMIN_USERNAME,
};
use crate::private::{JWT_SECRET, REFRESH_JWT_SECRET};
use crate::routes::authorization::token::create_token::encode_token_and_refresh;
use bcrypt::verify;
use mongodb::bson::oid::ObjectId;
use mongodb::error::Error as MongoError;
use mongodb::{bson, Database};
use mongodb::{Collection, Cursor};
use rocket::futures::future::ok;
use rocket::futures::TryStreamExt;
use rocket::serde::json::Json;

/**
 * MongoDB opporation
 */
impl MongoDB {
    pub fn new(database: Database) -> Self {
        MongoDB { database }
    }

    /**
     * Find user
     * parameters {find_by : &str, data_find_in : &str}
     * return : User
     */
    pub async fn find_user_by(
        &self,
        find_by: &str,
        data_find_in: &str,
    ) -> mongodb::error::Result<Option<User>> {
        let collection_user = self.database.collection::<User>("user");

        Ok(collection_user
            .find_one(bson::doc! { find_by: data_find_in }, None)
            .await?)
    }

    /**
     * Allow user can login
     * parameters {string_id : String}  
     * return : AllowError
     */
    pub async fn allow_user(&self, string_id: String) -> mongodb::error::Result<(AllowError)> {
        match ObjectId::parse_str(string_id) {
            Ok(object_id) => {
                let collection_user = self.database.collection::<User>("user");
                dbg!(
                    collection_user
                        .find_one_and_update(
                            bson::doc! {"_id" : object_id},
                            bson::doc! {"$set":{"allow" : true} },
                            None
                        )
                        .await?
                );
                Ok(AllowError::Ok())
            }
            Err(_) => Ok(AllowError::UserNotFound),
        }
    }

    /**
     * Get all of userlist
     * return : Vec<User>
     */
    pub async fn getUserList(&self) -> mongodb::error::Result<Vec<User>> {
        let collection = self.database.collection::<User>("user");
        let cursor = collection
            .find(None, None)
            .await
            .ok()
            .expect("Error getting list of users");

        let result = cursor.try_collect().await.unwrap();
        Ok(result)
    }

    /**
     * Reset password
     * parameters {email : String, new_password : String}
     * return : AllowError
     */
    pub async fn forget_password(
        &self,
        email: String,
        new_password: String,
    ) -> mongodb::error::Result<(AllowError)> {
        let collection_user = self.database.collection::<User>("user");
        match hash_text(new_password.clone(), 4) {
            Ok(hash_password) => {
                dbg!(
                    collection_user
                        .find_one_and_update(
                            bson::doc! {"email" : email},
                            bson::doc! {"$set":{"allow" : false, "password" : hash_password} },
                            None
                        )
                        .await?
                );
                Ok(AllowError::Ok())
            }
            Err(_) => Ok(AllowError::UserNotFound),
        }
    }

    /**
     * Change user information
     * parameters {string_id : String, user_infor : UserChangeRequest}
     * return : AllowError
     */
    pub async fn change_user(
        &self,
        string_id: String,
        user_infor: Option<Json<UserChangeRequest>>,
    ) -> mongodb::error::Result<(AllowError)> {
        match ObjectId::parse_str(string_id) {
            Ok(object_id) => match user_infor {
                None => Ok(AllowError::UserNotFound),
                Some(user_info) => {
                    let collection_user = self.database.collection::<User>("user");
                    let users_info = user_info.into_inner();
                    if users_info.password.is_empty() {
                        dbg!(
                            collection_user
                                .find_one_and_update(
                                    bson::doc! {"_id" : object_id},
                                    bson::doc! {"$set":{
                                         "username":users_info.username,
                                         "role" : users_info.role as i32,
                                         "allow" : users_info.allow,
                                         "first_name": users_info.first_name,
                                         "last_name" : users_info.last_name,
                                         "email" : users_info.email
                                    } },
                                    None
                                )
                                .await?
                        );
                        Ok(AllowError::Ok())
                    } else {
                        match hash_text(users_info.password.clone(), 4) {
                            Ok(hashpassword) => {
                                dbg!(
                                    collection_user
                                        .find_one_and_update(
                                            bson::doc! {"_id" : object_id},
                                            bson::doc! {"$set":{
                                                "username":users_info.username,
                                                "role" : users_info.role,
                                                "allow" : users_info.allow,
                                                "first_name": users_info.first_name,
                                                "last_name" : users_info.last_name,
                                                "email" : users_info.email,
                                                "password" : hashpassword
                                            } },
                                            None
                                        )
                                        .await?
                                );
                                Ok(AllowError::Ok())
                            }
                            Err(_) => Ok(AllowError::UserNotFound),
                        }
                    }
                }
            },
            Err(_) => Ok(AllowError::UserNotFound),
        }
    }

    /**
     * Login check for email and password
     * parameters {login_request : LoginRequest}
     * return : LoginError
     */
    pub async fn login(
        &self,
        login_request: Json<LoginRequest>,
    ) -> mongodb::error::Result<LoginError> {
        match Self::find_user_by(self, "email", &login_request.email).await {
            Ok(option_user) => match option_user {
                None => Ok(LoginError::WrongLogin),
                Some(user) => match verify(&login_request.password, &user.password) {
                    Ok(true) => {
                        if user.allow {
                            match encode_token_and_refresh(
                                user._id.clone(),
                                user.role,
                                JWT_SECRET,
                                REFRESH_JWT_SECRET,
                                EXPIRATION_REFRESH_TOKEN,
                                EXPIRATION_TOKEN,
                            ) {
                                Ok(tokens) => Ok(LoginError::Ok(LoginResponse {
                                    token: tokens,
                                    userID: user._id.to_hex(),
                                    role: user.role,
                                })),
                                Err(_) => Ok(LoginError::Unknown),
                            }
                        } else {
                            Ok(LoginError::NotPermit)
                        }
                    }
                    Ok(false) => Ok(LoginError::WrongPassword),
                    Err(_) => Ok(LoginError::WrongPassword),
                },
            },
            Err(_) => Ok(LoginError::WrongLogin),
        }
    }

    /**
     * User registeration
     * parameters {registration_request : RegistrationRequest}
     * return : RegistrationError
     */
    pub async fn registration(
        &self,
        registration_request: Json<RegistrationRequest>,
    ) -> mongodb::error::Result<RegistrationError> {
        let collection_user = self.database.collection::<User>("user");
        match find_user_by_email_username(
            self,
            &registration_request.email,
            &registration_request.username,
        )
        .await
        {
            FindUserBy::UserNotFound => match hash_text(registration_request.password.clone(), 4) {
                Ok(hash_password) => {
                    let user = User {
                        _id: ObjectId::new(),
                        email: registration_request.email.clone(),
                        username: registration_request.username.clone(),
                        first_name: registration_request.first_name.clone(),
                        last_name: registration_request.last_name.clone(),
                        password: hash_password,
                        allow: false,
                        role: registration_request.role.clone(),
                    };
                    collection_user.insert_one(&user, None).await?;
                    match encode_token_and_refresh(
                        user._id.clone(),
                        user.role,
                        JWT_SECRET,
                        REFRESH_JWT_SECRET,
                        EXPIRATION_REFRESH_TOKEN,
                        EXPIRATION_TOKEN,
                    ) {
                        Ok(tokens) => Ok(RegistrationError::Ok(tokens)),
                        Err(_) => Ok(RegistrationError::Unknown),
                    }
                }
                Err(_) => Ok(RegistrationError::WrongPassword),
            },
            FindUserBy::UserFoundByEmail => Ok(RegistrationError::AlreadyRegisteredByEmail),
            FindUserBy::UserFoundByLogin => Ok(RegistrationError::AlreadyRegisteredByLogin),
            FindUserBy::UserFoundByUsername => Ok(RegistrationError::AlreadyRegisteredByUsername),
        }
    }

    /**
     * Admin register new user
     * parameters : {registration_request : RegistrationRequest}
     * return : RegistrationError
     */
    pub async fn admin_user_registration(
        &self,
        registration_request: Json<RegistrationRequest>,
    ) -> mongodb::error::Result<RegistrationError> {
        let collection_user = self.database.collection::<User>("user");
        match find_user_by_email_username(
            self,
            &registration_request.email,
            &registration_request.username,
        )
        .await
        {
            FindUserBy::UserNotFound => match hash_text(registration_request.password.clone(), 4) {
                Ok(hash_password) => {
                    let user = User {
                        _id: ObjectId::new(),
                        email: registration_request.email.clone(),
                        first_name: registration_request.first_name.clone(),
                        last_name: registration_request.last_name.clone(),
                        username: registration_request.username.clone(),
                        password: hash_password,
                        allow: true,
                        role: registration_request.role.clone(),
                    };
                    collection_user.insert_one(&user, None).await?;
                    match encode_token_and_refresh(
                        user._id.clone(),
                        user.role,
                        JWT_SECRET,
                        REFRESH_JWT_SECRET,
                        EXPIRATION_REFRESH_TOKEN,
                        EXPIRATION_TOKEN,
                    ) {
                        Ok(tokens) => Ok(RegistrationError::Ok(tokens)),
                        Err(_) => Ok(RegistrationError::Unknown),
                    }
                }
                Err(_) => Ok(RegistrationError::WrongPassword),
            },
            FindUserBy::UserFoundByEmail => Ok(RegistrationError::AlreadyRegisteredByEmail),
            FindUserBy::UserFoundByLogin => Ok(RegistrationError::AlreadyRegisteredByLogin),
            FindUserBy::UserFoundByUsername => Ok(RegistrationError::AlreadyRegisteredByUsername),
        }
    }

    /**
     * Delete user using _id
     * parameters {user_id : String}
     * return : ()
     */
    pub async fn delete_user(&self, user_id: String) -> mongodb::error::Result<()> {
        let collection = self.database.collection::<User>("user");
        let obj_id = ObjectId::parse_str(user_id).unwrap();
        collection
            .delete_one(bson::doc! { "_id": obj_id }, None)
            .await?;
        Ok(())
    }

    /**
     * Get user's information using _id
     * parameters {user_id : String}
     * return : User
     */
    pub async fn get_userinfo(&self, user_id: String) -> mongodb::error::Result<Option<User>> {
        let obj_id = ObjectId::parse_str(user_id).unwrap();
        let collection_user = self.database.collection::<User>("user");
        let cursor = collection_user
            .find_one(bson::doc! { "_id": obj_id}, None)
            .await
            .ok();
        Ok(collection_user
            .find_one(bson::doc! { "_id": obj_id }, None)
            .await?)
    }

    /**
     * Create Superadmin
     * return : FeederError
     */
    pub async fn feeder(&self) -> mongodb::error::Result<FeederError> {
        match find_user_by_email_username(self, ADMIN_EMAIL, "SuperAdmin").await {
            FindUserBy::UserNotFound => match hash_text(ADMIN_PASSWORD.to_string(), 4) {
                Ok(hash_password) => {
                    let collection_user = self.database.collection::<User>("user");
                    let user = User {
                        _id: ObjectId::new(),
                        email: ADMIN_EMAIL.to_string(),
                        username: ADMIN_USERNAME.to_string(),
                        first_name: ADMIN_FIRST_NAME.to_string(),
                        last_name: ADMIN_LAST_NAME.to_string(),
                        password: hash_password,
                        allow: true,
                        role: 0,
                    };
                    collection_user.insert_one(&user, None).await?;
                    Ok(FeederError::Ok("Success".to_string()))
                }
                Err(_) => Ok(FeederError::AlreadyRegisteredByEmail),
            },
            FindUserBy::UserFoundByLogin => Ok(FeederError::AlreadyRegisteredByEmail),
            FindUserBy::UserFoundByEmail => Ok(FeederError::AlreadyRegisteredByEmail),
            FindUserBy::UserFoundByUsername => Ok(FeederError::AlreadyRegisteredByUsername),
        }
    }
}
