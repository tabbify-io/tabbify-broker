//! Tabbify credential broker (privileged in-FC). Holds the git cap-URL + forge
//! admin token, performs git/forge ops, and returns ONLY results. The agent uid
//! has no rwx on the socket and cannot read the cred files (0600 broker-uid).

pub mod authorized_keys;
pub mod creds;
pub mod dispatch;
pub mod forge;
pub mod git_ops;
pub mod http_ctrl;
pub mod request;
pub mod server;

pub use request::BrokerRequest;
