#![allow(clippy::missing_panics_doc)]

//! [`Endpoint`] builder.

use std::{fmt::Debug, net::SocketAddr, str::FromStr, sync::Arc};

use quinn::{
	CertificateChain, ClientConfig, ClientConfigBuilder, ServerConfigBuilder, TransportConfig,
};
use rustls::RootCertStore;

use crate::{Certificate, Dangerous, Endpoint, Error, PrivateKey, Result};

/// Holding configuration for [`Builder`] to build [`Endpoint`].
pub struct Builder {
	/// [`SocketAddr`] for [`Endpoint`](quinn::Endpoint) to bind to.
	address: SocketAddr,
	/// [`ClientConfig`] for [`Endpoint`](quinn::Endpoint).
	client: ClientConfigBuilder,
	/// [`ServerConfig`](quinn::ServerConfig) for [`Endpoint`](quinn::Endpoint).
	server: Option<ServerConfigBuilder>,
}

impl Debug for Builder {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Builder")
			.field("address", &self.address)
			.field("client", &"ClientConfigBuilder")
			.field(
				"server",
				&if self.server.is_some() {
					String::from("Some(ServerConfigBuilder)")
				} else {
					String::from("None")
				},
			)
			.finish()
	}
}

impl Default for Builder {
	fn default() -> Self {
		Self::new()
	}
}

impl Builder {
	/// Builds a new [`Builder`]. See [`Builder`] methods for defaults.
	#[must_use]
	pub fn new() -> Self {
		// build client
		let mut client = ClientConfig::default();
		#[allow(clippy::expect_used)]
		let crypto = Arc::get_mut(&mut client.crypto).expect("failed to build `ClientConfig`");

		// remove defaults
		crypto.root_store = RootCertStore::empty();
		crypto.ct_logs = None;

		Self {
			#[cfg(not(feature = "test"))]
			address: ([0; 8], 0).into(),
			// while testing always use the default loopback address
			#[cfg(feature = "test")]
			address: ([0, 0, 0, 0, 0, 0, 0, 1], 0).into(),
			client: ClientConfigBuilder::new(client),
			server: None,
		}
	}

	/// Set's the [`SocketAddr`]. Default is "\[::\]:0".
	pub fn set_address(&mut self, address: SocketAddr) -> &mut Self {
		self.address = address;
		self
	}

	/// Set's the [`SocketAddr`]. Default is "\[::\]:0".
	///
	/// # Errors
	/// [`Error::ParseAddress`] if the `address` couldn't be parsed.
	pub fn set_address_str(&mut self, address: &str) -> Result<&mut Self> {
		self.address = FromStr::from_str(address).map_err(Error::ParseAddress)?;
		Ok(self)
	}

	/// Adds a [`Certificate`] as a certificate authority for client
	/// [`connection`](Endpoint::connect)s.
	///
	/// # Errors
	/// - [`Error::Certificate`] if the [`Certificate`] couldn't be parsed
	/// - [`Error::InvalidCertificate`] if the [`Certificate`] couldn't be added
	///   as a certificate authority
	pub fn add_ca(&mut self, certificate: &Certificate) -> Result<&mut Self> {
		let certificate =
			quinn::Certificate::from_der(certificate.as_ref()).map_err(Error::Certificate)?;
		let _ = self
			.client
			.add_certificate_authority(certificate)
			.map_err(Error::InvalidCertificate)?;

		Ok(self)
	}

	/// Add a [`Certificate`] and [`PrivateKey`] for the server. This will add a
	/// listener to incoming [`Connection`](crate::Connection)s.
	///
	/// # Errors
	/// - [`Error::Certificate`] if the [`Certificate`] couldn't be parsed
	/// - [`Error::PrivateKey`] if the [`PrivateKey`] couldn't be parsed
	/// - [`Error::InvalidKeyPair`] if failed to pair the given [`Certificate`]
	///   and [`PrivateKey`]
	pub fn add_key_pair(
		&mut self,
		certificate: &Certificate,
		private_key: &PrivateKey,
	) -> Result<&mut Self> {
		// process keypair
		let certificate =
			quinn::Certificate::from_der(certificate.as_ref()).map_err(Error::Certificate)?;
		let chain = CertificateChain::from_certs(Some(certificate));
		let private_key = quinn::PrivateKey::from_der(Dangerous::as_ref(private_key))
			.map_err(Error::PrivateKey)?;

		// add keypair
		let _ = self
			.server
			.get_or_insert(ServerConfigBuilder::default())
			.certificate(chain, private_key)
			.map_err(Error::InvalidKeyPair)?;

		Ok(self)
	}

	/// Consumes [`Builder`] to build [`Endpoint`]. Must be called from inside
	/// the Tokio [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`Error::BindSocket`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// If not called from inside the Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	#[allow(clippy::unwrap_in_result)]
	pub fn build(self) -> Result<Endpoint, (Error, Self)> {
		// build transport
		let mut transport = TransportConfig::default();

		// set transport defaults
		#[allow(clippy::expect_used)]
		let _ = transport
			.allow_spin(false)
			.datagram_receive_buffer_size(None)
			.max_concurrent_bidi_streams(1)
			.expect("can't be bigger then `VarInt`")
			.max_concurrent_uni_streams(0)
			.expect("can't be bigger then `VarInt`");

		let transport = Arc::new(transport);

		match {
			// to be able to reuse `Builder` on failure, we have to preserve quinn builders
			let mut client = self.client.clone().build();
			client.transport = Arc::clone(&transport);

			let server = self.server.as_ref().map(|server| {
				let mut server = server.clone().build();
				server.transport = transport;
				server
			});

			Endpoint::new(self.address, client, server)
		} {
			Ok(endpoint) => Ok(endpoint),
			Err(error) => Err((error, Self {
				address: self.address,
				client: self.client,
				server: self.server,
			})),
		}
	}
}

#[cfg(test)]
mod test {
	use anyhow::Result;

	use super::*;

	#[tokio::test]
	async fn default() -> Result<()> {
		let _endpoint = Builder::default().build().map_err(|(error, _)| error)?;
		Ok(())
	}

	#[tokio::test]
	async fn new() -> Result<()> {
		let _endpoint = Builder::new().build().map_err(|(error, _)| error)?;
		Ok(())
	}

	#[tokio::test]
	async fn address() -> Result<()> {
		let mut builder = Builder::new();
		let _ = builder.set_address(([0, 0, 0, 0, 0, 0, 0, 1], 5000).into());
		let endpoint = builder.build().map_err(|(error, _)| error)?;

		assert_eq!(
			"[::1]:5000".parse::<SocketAddr>()?,
			endpoint.local_address()?,
		);

		Ok(())
	}

	#[tokio::test]
	async fn address_str() -> Result<()> {
		let mut builder = Builder::new();
		let _ = builder.set_address_str("[::1]:5001")?;
		let endpoint = builder.build().map_err(|(error, _)| error)?;

		assert_eq!(
			"[::1]:5001".parse::<SocketAddr>()?,
			endpoint.local_address()?
		);

		Ok(())
	}

	#[tokio::test]
	async fn ca_key_pair() -> Result<()> {
		use futures_util::StreamExt;

		let (certificate, private_key) = crate::generate_self_signed("test");

		// build client
		let mut builder = Builder::new();
		let _ = builder.add_ca(&certificate)?;
		let client = builder.build().map_err(|(error, _)| error)?;

		// build server
		let mut builder = Builder::new();
		let _ = builder.add_key_pair(&certificate, &private_key)?;
		let mut server = builder.build().map_err(|(error, _)| error)?;

		// test connection
		let _connection = client.connect(server.local_address()?, "test").await?;
		let _connection = server.next().await.expect("client dropped")?;

		Ok(())
	}
}
