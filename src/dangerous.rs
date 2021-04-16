//! Security-sensitive settings are hidden behind these traits. Be careful!

pub use crate::{certificate::Dangerous as Certificate, quic::Dangerous as Builder};
