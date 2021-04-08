//! QUIC enabled socket implementation.

mod connection;
mod endpoint;
mod task;

pub use connection::{Connection, Incoming, Receiver, Sender};
pub use endpoint::{Builder, Endpoint};
use task::Task;
