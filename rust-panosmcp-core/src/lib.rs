//! Transport-independent PAN-OS client and tool foundations.

pub mod client;
pub mod error;
pub mod inventory;
pub mod mutation;
pub mod observability;
pub(crate) mod redact;
pub mod tools;
pub mod version_advisory;
pub mod xml;

pub use error::{PanosMcpError, Result};
