use crate::database::connect_to_db::MongoDB;
use crate::database::FindUserBy;
use bcrypt::hash;
use rocket::http::Status;

//check valid text
pub fn check_valid_text(text: &str, max_size: usize, min_size: usize) -> bool {
    return if !text.is_empty() && text.len() <= max_size && text.len() >= min_size {
        true
    } else {
        false
    };
}

//check valid name
pub fn check_valid_name(text: &str, max_size: usize, min_size: usize) -> bool {
    return if text.is_empty() || text.len() <= max_size && text.len() >= min_size {
        true
    } else {
        false
    };
}

//hash text
pub fn hash_text(text: String, cost: u32) -> Result<String, Status> {
    return match hash(text, cost) {
        Ok(hash_text) => Ok(hash_text),
        Err(_) => Err(Status::BadRequest),
    };
}


// find user by email 
// pub async fn find_user_by_email_username (
//     database: &MongoDB,
//     email: &str,
//     username : &str,
// ) -> FindUserBy {
//     match database.find_user_by("email", email).await {
//         Ok(None) =>FindUserBy::UserNotFound,
//         Ok(Some(_)) => FindUserBy::UserFoundByEmail,
//         Err(_) => FindUserBy::UserFoundByLogin,
//     }
// }

// find user by email 
pub async fn find_user_by_email_username (
    database: &MongoDB,
    email: &str,
    username : &str,
) -> FindUserBy {
    match database.find_user_by("email", email).await {
        Ok(None) =>{
            match database.find_user_by("username", username).await {
                        Ok(None) =>FindUserBy::UserNotFound,
                        Ok(Some(_)) => FindUserBy::UserFoundByUsername,
                        Err(_) => FindUserBy::UserFoundByLogin,
                    }    
        },
        Ok(Some(_)) => FindUserBy::UserFoundByEmail,
        Err(_) => FindUserBy::UserFoundByLogin,
    }
}


//check data from request auth
pub fn check_data_from_auth_header(auth_header: Option<&str>) -> Result<Vec<&str>, ()> {
    return if let Some(auth_string) = auth_header {
        let vec_header = auth_string.split_whitespace().collect::<Vec<_>>();
        if vec_header.len() != 2
            && vec_header[0] == "Bearer"
            && !vec_header[0].is_empty()
            && !vec_header[1].is_empty()
        {
            Err(())
        } else {
            Ok(vec_header)
        }
    } else {
        Err(())
    };
}