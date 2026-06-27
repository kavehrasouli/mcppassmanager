use rusqlite::{Connection, Result};

pub fn init_db(conn: &Connection
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS salt (
            id      INTEGER PRIMARY KEY,
            value   BLOB NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS credentials (
            site        TEXT PRIMARY KEY,
            username    BLOB NOT NULL,
            password    BLOB NOT NULL
        )",
        [],
    )?;

    Ok(())
}

pub fn store_salt(conn: &Connection, 
    salt: &[u8; 16]) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO salt (id, value) VALUES (1, ?1)",
        [salt.as_slice()],
    )?;
    Ok(())
}

pub fn load_salt(conn: &Connection) -> Option<[u8; 16]> {
    let result: Result<Vec<u8>, _> = conn.query_row(
        "SELECT value FROM salt WHERE id = 1",
        [],
        |row| row.get(0)
    );

    match result {
        Ok(bytes) => bytes.try_into().ok(),
        Err(_)    => None,
    }
}

pub fn store_credential(conn: &Connection, site: &str, 
    username: &[u8], ciphertext: &[u8]) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO credentials (site, username, password) VALUES (?1, ?2, ?3)",
        rusqlite::params![site, username, ciphertext],
    )?;
    Ok(())
}

pub fn get_credential(conn: &Connection, site: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    conn.query_row(
        "SELECT username, password FROM credentials WHERE site = ?1",
        rusqlite::params![site],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).ok()
}

pub fn list_sites(conn: &Connection) -> Vec<String> {
    let mut stmt = conn.prepare("SELECT site FROM credentials").unwrap();
    stmt.query_map([], |row| row.get(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
}

pub fn delete_credential(conn: &Connection, 
    site: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM credentials WHERE site = ?1",
        rusqlite::params![site],
    )?;
    Ok(())
}