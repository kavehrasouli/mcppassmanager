mod crypto;
mod db;

use rusqlite::Connection;

pub fn store_credentials(
    conn: &Connection,
    site: &str,
    username: &str,
    password: &str,
    key: &[u8; 32]
) -> Result<(), rusqlite::Error> {
    let encrypted_username = crypto::encrypt(username, key);
    let encrypted_password = crypto::encrypt(password, key);
    db::store_credential(conn, site, &encrypted_username, &encrypted_password)
}

pub fn get_credentials(
    conn: &Connection,
    site: &str,
    key: &[u8; 32]
) -> Option<(String, String)> {
    let (enc_username, enc_password) = db::get_credential(conn, site)?;
    let username = crypto::decrypt(&enc_username, key).ok()?;
    let password = crypto::decrypt(&enc_password, key).ok()?;
    Some((username, password))
}