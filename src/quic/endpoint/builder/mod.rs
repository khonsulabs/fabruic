//! [`Endpoint`] builder.

mod config;

use std::{fmt::Debug, net::SocketAddr, str::FromStr};

pub(super) use config::Config;
use quinn::{CertificateChain, ServerConfigBuilder};

use crate::{Certificate, Endpoint, Error, PrivateKey, Result};

#[derive(Debug)]
/// Holding configuration for [`Builder`] to build [`Endpoint`].
pub struct Builder {
	/// [`SocketAddr`] for [`Endpoint`](quinn::Endpoint) to bind to.
	address: SocketAddr,
	/// Custom CA [`Certificate`]s.
	ca_store: Vec<Certificate>,
	/// Key-pair for the server.
	key_pair: Option<(Certificate, PrivateKey)>,
	/// Persistent configuration passed to the [`Endpoint`]
	config: Config,
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
			// equals to `[::ffff:127.0.0.1]:0`
			#[cfg(feature = "test")]
			address: ([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1], 0).into(),
			ca_store: Vec::new(),
			key_pair: None,
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

	/// Set a [`Certificate`] and [`PrivateKey`] for the server. This will add a
	/// listener to incoming [`Connection`](crate::Connection)s.
	pub fn set_key_pair(&mut self, certificate: Certificate, private_key: PrivateKey) -> &mut Self {
		self.key_pair = Some((certificate, private_key));
		self
	}

	/// Set the application-layer protocols to accept, in order of descending
	/// preference. When set, clients which don't declare support for at least
	/// one of the supplied protocols will be rejected.
	///
	/// See [`Connection::protocol`](crate::Connection::protocol).
	pub fn set_protocols<P: Into<Vec<Vec<u8>>>>(&mut self, protocols: P) -> &mut Self {
		self.config.set_protocols(protocols);
		self
	}

	/// Forces [`Endpoint::connect`] to use [`trust-dns`](trust_dns_resolver).
	pub fn set_trust_dns(&mut self, trust_dns: bool) -> &mut Self {
		self.config.set_trust_dns(trust_dns);
		self
	}

	/// Consumes [`Builder`] to build [`Endpoint`]. Must be called from inside
	/// the Tokio [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`Error::BindSocket`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// - if the given [`Certificate`] is invalid. Can't happen if the
	///   [`Certificate`] was properly validated through
	///   [`Certificate::from_der`]
	/// - if not called from inside the Tokio
	///   [`Runtime`](tokio::runtime::Runtime)
	pub fn build(self) -> Result<Endpoint, (Error, Self)> {
		match {
			// build client
			let client = self.config.new_client(self.ca_store.iter());

			// build server only if we have a key-pair
			let server = self.key_pair.as_ref().map(|(certificate, private_key)| {
				let mut server = ServerConfigBuilder::default();

				// build key-pair
				let certificate = quinn::Certificate::from_der(certificate.as_ref())
					.expect("`Certificate` couldn't be parsed");
				let chain = CertificateChain::from_certs(Some(certificate));
				let private_key =
					quinn::PrivateKey::from_der(crate::dangerous::Certificate::as_ref(private_key))
						.expect("`PrivateKey` couldn't be parsed");
				// add key-pair
				let _ = server
					.certificate(chain, private_key)
					.expect("`CertificateChain` couldn't be verified");

				// set protocols
				if !self.config.protocols().is_empty() {
					let _ = server.protocols(
						self.config
							.protocols()
							.iter()
							.map(Vec::as_slice)
							.collect::<Vec<_>>()
							.as_slice(),
					);
				}

				let mut server = server.build();

				// set transport
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

/// Security-sensitive configuration for [`Builder`].
pub trait Dangerous {
	/// Adds a [`Certificate`] into the default certificate authority store for
	/// [`connection`](Endpoint::connect)ing to a server.
	///
	/// # Security
	/// Managing your own CA root store can make sense if a private CA is used.
	/// Otherwise use [`Endpoint::connect_pinned`].
	fn add_ca(builder: &mut Self, certificate: Certificate);
}

impl Dangerous for Builder {
	fn add_ca(builder: &mut Self, certificate: Certificate) {
		builder.ca_store.push(certificate);
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
		Dangerous::add_ca(&mut builder, certificate.clone());
		let client = builder.build().map_err(|(error, _)| error)?;

		// build server
		let mut builder = Builder::new();
		let _ = builder.set_key_pair(certificate, private_key);
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
