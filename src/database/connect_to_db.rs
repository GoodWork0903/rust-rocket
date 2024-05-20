use mongodb::{ options::ClientOptions, Client, Database};
use rocket::fairing::AdHoc;

use crate::private::URL_DB;

/**
 * To conncet MongoDB
 */
pub struct MongoDB {
    pub(crate) database: Database,
}

/**
 * This function for connetion
 */
pub async fn init() -> AdHoc {
    AdHoc::on_ignite("Connect to MongoDB cluster", |rocket| async {
        match connect().await {
            Ok(database) => rocket.manage(MongoDB::new(database)),
            Err(error) => {
                panic!("Cannot connect to MDB instance:: {:?}", error)
            }
        }
    })
}

/**
 * Create new usermanger collection
 */
async fn connect() -> mongodb::error::Result<Database> {
    let client_options = ClientOptions::parse(URL_DB).await?;
    let client = Client::with_options(client_options)?;
    Ok(client.database("usermanager"))
}
