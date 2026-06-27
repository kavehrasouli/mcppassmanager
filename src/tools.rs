use rmcp::{ServerHandler, model::ServerInfo, schemars, tool};
use serde::Deserialize;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use crate::{db, crypto};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StoreInput {
    #[schemars(description = "Website name or URL")]
    pub site: String,
    #[schemars(description = "Username or email")]
    pub username: String,
    #[schemars(description = "Password to store")]
    pub password: String,
    #[schemars(description = "Master password to encrypt with")]
    pub master_password: String
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetInput {
    #[schemars(description = "Website name or URL")]
    pub site: String,
    #[schemars(description = "Master password to decrypt with")]
    pub master_password: String
}

#[derive(Clone)]
pub struct PassManager {
    conn: Arc<Mutex<Connection>>
}

#[tool(tool_box)]
impl PassManager {
    pub fn new(conn: Connection) -> Self {
        db::init_db(&conn).unwrap();
        Self {conn: Arc::new(Mutex::new(conn))}
    }

    #[tool(description = "Store an encrypted credential for a site")]
    fn store_credential(&self, #[tool(aggr)] input: StoreInput) -> String {
        let conn = self.conn.lock().unwrap();
        let salt = match db::load_salt(&conn) {
            Some(s) => s,
            None => {
                let s = crypto::generate_salt();
                db::store_salt(&conn, &s).unwrap();
                s
            }
        };
        let key = crypto::derive_key(&input.master_password, &salt);
        let enc_username = crypto::encrypt(&input.username, &key);
        let enc_password = crypto::encrypt(&input.password, &key);
        match db::store_credential(&conn, &input.site, &enc_username, &enc_password) {
            Ok(_)  => format!("Store credentials for {}", input.site),
            Err(e) => format!("Error: {}", e)
        }
    }

    #[tool(description = "Retrieve and decrypt credentials for a site")]
    fn get_credential(&self, #[tool(aggr)] input: GetInput) -> String {
        let conn = self.conn.lock().unwrap();
        let salt = match db::load_salt(&conn) {
            Some(s) => s,
            None    => return "No credentials stored yet".to_string(),
        };
        let key = crypto::derive_key(&input.master_password, &salt);
        let result = db::get_credential(&conn, &input.site)
            .and_then(|(enc_u, enc_p)| {
                let username = crypto::decrypt(&enc_u, &key).ok()?;
                let password = crypto::decrypt(&enc_p, &key).ok()?;
                Some((username, password))
            });
        match result {
            Some((username, password)) => format!("username: {}\npassword: {}", username, password),
            None => format!("No credentials found for {}", input.site),
        }
    }

    #[tool(description = "List all stored site names")]
    fn list_sites(&self) -> String {
        let conn = self.conn.lock().unwrap();
        let sites = db::list_sites(&conn);
        if sites.is_empty() {
            "No credentials stored".to_string()
        } else {
            sites.join("\n")
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for PassManager {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("A secure pass manager".into()),
            ..Default::default()
        }
    }
}