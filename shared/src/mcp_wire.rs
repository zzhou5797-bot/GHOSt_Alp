//! Structured request/response types for the Ghost MCP transport.
//!
//! These messages are carried inside length-prefixed JSON frames over a
//! mutually-authenticated QUIC connection.  The transport is intentionally
//! separate from MCP itself: the bridge speaks MCP on stdio/HTTP and converts
//! tool calls into these small Ghost-native requests.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AgentRequest {
    Authenticate {
        token: String,
    },
    SystemInfo,
    ListDirectory {
        path: String,
    },
    ReadFile {
        path: String,
        offset: Option<usize>,
        length: Option<usize>,
    },
    WriteFile {
        path: String,
        content: String,
        create_parents: bool,
    },
    RunCommand {
        command: String,
        cwd: Option<String>,
        timeout_ms: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AgentResponse {
    pub fn success(result: Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(error.into()),
        }
    }
}
