mod crypto;
mod db;
mod tools;

use tools::PassManager;
use rmcp::ServiceExt;
use rusqlite::Connection;
use tokio::io::{stdin, stdout};

#[tokio::main]
async fn main() {
    let db_path = dirs::data_dir()
        .expect("could not find data directory")
        .join("passmanager")
        .join("passwords.db");
    std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let conn = Connection::open(&db_path).unwrap();
    let service = PassManager::new(conn);
    let transport = (stdin(), stdout());
    service.serve(transport).await.unwrap();
}