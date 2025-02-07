pub mod authorization;
pub mod routes;
pub mod validator_authorization;


pub enum TypeValidDataFromRegistration {
    Ok,
    BadLogin,
    BadPassword,
    BadMail,
}

pub enum TypeValidTwoStr {
    Ok,
    BadFirst,
    BadSecond,
}

pub enum TypeValidMail {
    Ok,
    BadMail,
}
