//! Intermediate [`Connection`] object to query
//! [`protocol`](Connecting::protocol).

use std::net::SocketAddr;

use quinn::{crypto::rustls::HandshakeData, NewConnection};
use serde::{de::DeserializeOwned, Serialize};

use crate::{error, Connection};

/// Represent's an intermediate state to build a [`Connection`].
#[must_use = "`Connecting` does nothing unless accepted with `Connecting::accept`"]
#[derive(Debug)]
pub struct Connecting(quinn::Connecting);

impl Connecting {
	/// Builds a new [`Connecting`].
	pub(in crate::quic) const fn new(connecting: quinn::Connecting) -> Self {
		Self(connecting)
	}

	/// The negotiated application protocol. See
	/// [`Builder::set_protocols`](crate::Builder::set_protocols).
	///
	/// # Errors
	/// [`error::Connecting`] if the [`Connection`] failed to be established.
	pub async fn protocol(&mut self) -> Result<Option<Vec<u8>>, error::Connecting> {
		self.0
			.handshake_data()
			.await
			.map(|data| {
				data.downcast_ref::<HandshakeData>()
					.and_then(|data| data.protocol.clone())
			})
			.map_err(error::Connecting)
	}

	/// The peer's address. Clients may change addresses at will, e.g. when
	/// switching to a cellular internet connection.
	#[must_use]
	pub fn remote_address(&self) -> SocketAddr {
		self.0.remote_address()
	}

	/// Accept the [`Connection`] with the given `T` as the type negotiator for
	/// new streams.
	///
	/// # Errors
	/// [`error::Connecting`] if the [`Connection`] failed to be established.
	pub async fn accept<T: DeserializeOwned + Serialize + Send + 'static>(
		self,
	) -> Result<Connection<T>, error::Connecting> {
		self.0
			.await
			.map(
				|NewConnection {
				     connection,
				     bi_streams,
				     ..
				 }| Connection::new(connection, bi_streams),
			)
			.map_err(error::Connecting)
	}
}
