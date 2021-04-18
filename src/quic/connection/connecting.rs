//! Intermediate [`Connection`] object to query
//! [`protocol`](Connecting::protocol).

use quinn::NewConnection;
use serde::{de::DeserializeOwned, Serialize};

use crate::{Connection, Error, Result};

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
	/// [`Error::Connecting`] if the [`Connection`] failed to be established.
	pub async fn protocol(&mut self) -> Result<Option<Vec<u8>>> {
		self.0
			.handshake_data()
			.await
			.map(|data| data.protocol)
			.map_err(Error::Connecting)
	}

	/// Accept the [`Connection`] with the given `T` as the type negotiator for
	/// new streams.
	///
	/// # Errors
	/// [`Error::Connecting`] if the [`Connection`] failed to be established.
	pub async fn accept<T: DeserializeOwned + Serialize + Send + 'static>(
		self,
	) -> Result<Connection<T>> {
		self.0
			.await
			.map(
				|NewConnection {
				     connection,
				     bi_streams,
				     ..
				 }| Connection::new(connection, bi_streams),
			)
			.map_err(Error::Connecting)
	}
}