mod crypto;
mod db;
mod tools;

use tools::PassManager;
use rmcp::ServiceExt;
use rusqlite::Connection;
use tokio::io::{stdin, stdout};

#[tokio::main]
async fn main() {
    let conn = Connection::open("passwords.db").unwrap();
    let service = PassManager::new(conn);
    let transport = (stdin(), stdout());
    service.serve(transport).await.unwrap();
}