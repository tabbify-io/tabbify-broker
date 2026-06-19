//! Tabbify credential broker (privileged in-FC). Holds the git cap-URL + forge
//! admin token, performs git/forge ops, and returns ONLY results. The agent uid
//! has no rwx on the socket and cannot read the cred files (0600 broker-uid).

pub mod creds;
pub mod git_ops;
