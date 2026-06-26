mod crypto;
mod db;

use rusqlite::Connection;

pub fn get_credentials(
    conn: &Connection,
    site: &str,
    key: &[u8; 32]) -> Option<(String, String)> 
{
    let (username, ciphertext) = db::get_credential(conn, site)?;
    let password = crypto::decrypt(&ciphertext,key).ok()?;
    Some((username, password))
}