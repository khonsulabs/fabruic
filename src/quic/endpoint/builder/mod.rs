#![allow(clippy::missing_panics_doc)]

//! [`Endpoint`] builder.

mod config;

use std::{fmt::Debug, net::SocketAddr, str::FromStr};

pub(super) use config::Config;
use quinn::{CertificateChain, ClientConfigBuilder, ServerConfigBuilder};

use crate::{Certificate, Dangerous, Endpoint, Error, PrivateKey, Result};

/// Holding configuration for [`Builder`] to build [`Endpoint`].
pub struct Builder {
	/// [`SocketAddr`] for [`Endpoint`](quinn::Endpoint) to bind to.
	address: SocketAddr,
	/// [`ClientConfig`](quinn::ClientConfig) for [`Endpoint`](quinn::Endpoint).
	client: ClientConfigBuilder,
	/// [`ServerConfig`](quinn::ServerConfig) for [`Endpoint`](quinn::Endpoint).
	server: Option<ServerConfigBuilder>,
	/// Persistent configuration passed to the [`Endpoint`]
	config: Config,
}

impl Debug for Builder {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Builder")
			.field("address", &self.address)
			.field("client", &"ClientConfigBuilder")
			.field(
				"server",
				&if self.server.is_some() {
					"Some(ServerConfigBuilder)"
				} else {
					"None"
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
		let config = Config::new();

		Self {
			#[cfg(not(feature = "test"))]
			address: ([0; 8], 0).into(),
			// while testing always use the default loopback address
			// equals too `[::ffff:127.0.0.1]:0`
			#[cfg(feature = "test")]
			address: ([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1], 0).into(),
			client: config.new_client_builder(),
			server: None,
			config,
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

	/// Adds a [`Certificate`] into the default certificate authority store for
	/// client [`connection`](Endpoint::connect)s.
	///
	/// # Panics
	/// Panics if the given [`Certificate`] is invalid. Can't happen if the
	/// [`Certificate`] was properly validated through
	/// [`Certificate::from_der`].
	#[allow(clippy::expect_used)]
	pub fn add_ca(&mut self, certificate: &Certificate) -> &mut Self {
		let certificate = quinn::Certificate::from_der(certificate.as_ref())
			.expect("`Certificate` couldn't be parsed");
		let _ = self
			.client
			.add_certificate_authority(certificate)
			.expect("`Certificate` couldn't be added as a CA");

		self
	}

	/// Add a [`Certificate`] and [`PrivateKey`] for the server. This will add a
	/// listener to incoming [`Connection`](crate::Connection)s.
	///
	/// # Panics
	/// Panics if the given [`Certificate`] is invalid. Can't happen if the
	/// [`Certificate`] was properly validated through
	/// [`Certificate::from_der`].
	#[allow(clippy::expect_used)]
	pub fn add_key_pair(
		&mut self,
		certificate: &Certificate,
		private_key: &PrivateKey,
	) -> &mut Self {
		// process keypair
		let certificate = quinn::Certificate::from_der(certificate.as_ref())
			.expect("`Certificate` couldn't be parsed");
		let chain = CertificateChain::from_certs(Some(certificate));
		let private_key = quinn::PrivateKey::from_der(Dangerous::as_ref(private_key))
			.expect("`PrivateKey` couldn't be parsed");

		// add keypair
		let _ = self
			.server
			.get_or_insert(ServerConfigBuilder::default())
			.certificate(chain, private_key)
			.expect("`CertificateChain` couldn't be verified");

		self
	}

	/// Set the application-layer protocols to accept, in order of descending
	/// preference. When set, clients which don't declare support for at least
	/// one of the supplied protocols will be rejected.
	///
	/// See [`Connection::protocol`](crate::Connection::protocol).
	pub fn set_protocols(&mut self, protocols: &[&[u8]]) -> &mut Self {
		let _ = self.client.protocols(protocols);
		let _ = self
			.server
			.get_or_insert(ServerConfigBuilder::default())
			.protocols(protocols);

		self.config.set_protocols(protocols);

		self
	}

	/// Forces [`Endpoint::connect`] to use [`trust-dns`](trust_dns_resolver).
	pub fn set_trust_dns(&mut self, trust_dns: bool) {
		self.config.set_trust_dns(trust_dns);
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
		match {
			// to be able to reuse `Builder` on failure, we have to preserve quinn builders
			let mut client = self.client.clone().build();
			client.transport = self.config.transport();

			let server = self.server.as_ref().map(|server| {
				let mut server = server.clone().build();
				server.transport = self.config.transport();
				server
			});

			Endpoint::new(self.address, client, server, self.config.clone())
		} {
			Ok(endpoint) => Ok(endpoint),
			Err(error) => Err((error, self)),
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
		let _ = builder.set_address(([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1], 5000).into());
		let endpoint = builder.build().map_err(|(error, _)| error)?;

		assert_eq!(
			"[::ffff:127.0.0.1]:5000".parse::<SocketAddr>()?,
			endpoint.local_address()?,
		);

		Ok(())
	}

	#[tokio::test]
	async fn address_str() -> Result<()> {
		let mut builder = Builder::new();
		let _ = builder.set_address_str("[::ffff:127.0.0.1]:5001")?;
		let endpoint = builder.build().map_err(|(error, _)| error)?;

		assert_eq!(
			"[::ffff:127.0.0.1]:5001".parse::<SocketAddr>()?,
			endpoint.local_address()?
		);

		Ok(())
	}

	#[tokio::test]
	async fn ca_key_pair() -> Result<()> {
		use futures_util::StreamExt;

		let (certificate, private_key) = crate::generate_self_signed("localhost");

		// build client
		let mut builder = Builder::new();
		let _ = builder.add_ca(&certificate);
		let client = builder.build().map_err(|(error, _)| error)?;

		// build server
		let mut builder = Builder::new();
		let _ = builder.add_key_pair(&certificate, &private_key);
		let mut server = builder.build().map_err(|(error, _)| error)?;

		// test connection
		let _connection = client
			.connect(format!(
				"quic://localhost:{}",
				server.local_address()?.port()
			))
			.await?
			.accept::<()>()
			.await?;
		let _connection = server
			.next()
			.await
			.expect("client dropped")
			.accept::<()>()
			.await?;

		Ok(())
	}
}
