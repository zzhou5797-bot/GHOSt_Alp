use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    /// Execute a command (msg from Client -> Server)
    Command(String),
    /// Standard Output (msg from Server -> Client)
    Output(String),
    /// Standard Error (msg from Server -> Client)
    Error(String),
    /// Exit the session
    Exit,
}
