//! [`Endpoint`] builder.

mod config;
use std::{fmt::Debug, net::SocketAddr, sync::Arc};

pub(super) use config::Config;
use quinn::{CertificateChain, ServerConfigBuilder};
use rustls::{ClientCertVerified, ClientCertVerifier, DistinguishedNames, TLSError};
use serde::{Deserialize, Serialize};
use webpki::DNSName;

use crate::{error, Certificate, Endpoint, KeyPair, Result};

/// Helper for constructing an [`Endpoint`].
///
/// # Examples
/// ```
/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
/// use fabruic::{Builder, Store};
///
/// let mut builder = Builder::new();
/// builder
/// 	.set_protocols([b"test".to_vec()])
/// 	.set_store(Store::Os);
///
/// let endpoint = builder.build()?;
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct Builder {
	/// [`SocketAddr`] for [`Endpoint`](quinn::Endpoint) to bind to.
	address: SocketAddr,
	/// Custom root [`Certificate`]s.
	root_certificates: Vec<Certificate>,
	/// Server certificate ley-pair.
	server_key_pair: Option<KeyPair>,
	/// Client certificate key-pair.
	client_key_pair: Option<KeyPair>,
	/// [`Store`] option.
	store: Store,
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
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Builder;
	///
	/// let mut endpoint = Builder::new().build()?;
	/// # Ok(()) }
	/// ```
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
			root_certificates: Vec::new(),
			server_key_pair: None,
			client_key_pair: None,
			store: Store::Embedded,
			config,
		}
	}

	/// Set's the [`SocketAddr`] to bind to.
	///
	/// Default is "\[::\]:0".
	///
	/// # Examples
	/// ```
	/// # fn main() -> anyhow::Result<()> {
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	/// builder.set_address("[::1]:0".parse()?);
	/// # Ok(()) }
	/// ```
	pub fn set_address(&mut self, address: SocketAddr) -> &mut Self {
		self.address = address;
		self
	}

	/// Returns the [`SocketAddr`] to bind to.
	///
	/// See [`set_address`](Self::set_address).
	///
	/// # Examples
	/// ```
	/// # fn main() -> anyhow::Result<()> {
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	///
	/// let address = "[::1]:0".parse()?;
	/// builder.set_address(address);
	/// assert_eq!(builder.address(), &address);
	/// # Ok(()) }
	/// ```
	#[must_use]
	pub const fn address(&self) -> &SocketAddr {
		&self.address
	}

	/// Set a server certificate [`KeyPair`], use [`None`] to
	/// remove any server certificate.
	///
	/// [`Endpoint`] won't listen to any incoming
	/// [`Connection`](crate::Connection)s without a server certificate.
	///
	/// Default is [`None`].
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, KeyPair};
	///
	/// let mut builder = Builder::new();
	/// builder.set_server_key_pair(Some(KeyPair::new_self_signed("test")));
	/// ```
	pub fn set_server_key_pair(&mut self, key_pair: Option<KeyPair>) -> &mut Self {
		self.server_key_pair = key_pair;
		self
	}

	/// Returns the server certificate [`KeyPair`].
	///
	/// See [`set_server_key_pair`](Self::set_server_key_pair).
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, KeyPair};
	///
	/// let mut builder = Builder::new();
	///
	/// let key_pair = KeyPair::new_self_signed("test");
	/// builder.set_server_key_pair(Some(key_pair.clone()));
	/// assert_eq!(builder.server_key_pair(), &Some(key_pair))
	/// ```
	#[must_use]
	pub const fn server_key_pair(&self) -> &Option<KeyPair> {
		&self.server_key_pair
	}

	/// Set a client certificate [`KeyPair`], use [`None`] to
	/// remove any client certificate.
	///
	/// Default is [`None`].
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, KeyPair};
	///
	/// let mut builder = Builder::new();
	/// builder.set_client_key_pair(Some(KeyPair::new_self_signed("test")));
	/// ```
	pub fn set_client_key_pair(&mut self, key_pair: Option<KeyPair>) -> &mut Self {
		self.client_key_pair = key_pair;
		self
	}

	/// Returns the client certificate [`KeyPair`].
	///
	/// See [`set_client_key_pair`](Self::set_client_key_pair).
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, KeyPair};
	///
	/// let mut builder = Builder::new();
	///
	/// let key_pair = KeyPair::new_self_signed("test");
	/// builder.set_client_key_pair(Some(key_pair.clone()));
	/// assert_eq!(builder.client_key_pair(), &Some(key_pair))
	/// ```
	#[must_use]
	pub const fn client_key_pair(&self) -> &Option<KeyPair> {
		&self.client_key_pair
	}

	/// Set the protocols to accept, in order of descending preference. When
	/// set, clients which don't declare support for at least one of the
	/// supplied protocols will be rejected.
	///
	/// See [`Connection::protocol`](crate::Connection::protocol).
	///
	/// Default contains no protocols.
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	/// builder.set_protocols([b"test".to_vec()]);
	/// ```
	pub fn set_protocols<P: Into<Vec<Vec<u8>>>>(&mut self, protocols: P) -> &mut Self {
		self.config.set_protocols(protocols);
		self
	}

	/// Returns the set protocols.
	///
	/// See [`set_protocols`](Self::set_protocols).
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	///
	/// let protocols = [b"test".to_vec()];
	/// builder.set_protocols(protocols.clone());
	/// assert_eq!(builder.protocols(), protocols)
	/// ```
	#[must_use]
	pub fn protocols(&self) -> &[Vec<u8>] {
		self.config.protocols()
	}

	/// Controls the use of [`trust-dns`](trust_dns_resolver) for
	/// [`Endpoint::connect`].
	///
	/// Default is [`true`] if the crate feature <span
	///   class="module-item stab portability"
	///   style="display: inline; border-radius: 3px; padding: 2px; font-size:
	/// 80%; line-height: 1.2;" ><code>trust-dns</code></span> is enabled.
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	/// builder.set_trust_dns(false);
	/// ```
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub fn set_trust_dns(&mut self, enable: bool) -> &mut Self {
		self.config.set_trust_dns(enable);
		self
	}

	/// Disables the use of [`trust-dns`](trust_dns_resolver) for
	/// [`Endpoint::connect`] despite the activated crate feature.
	///
	/// Default is enabled if the crate feature <span
	///   class="module-item stab portability"
	///   style="display: inline; border-radius: 3px; padding: 2px; font-size:
	/// 80%; line-height: 1.2;" ><code>trust-dns</code></span> is enabled.
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	/// builder.disable_trust_dns();
	/// ```
	pub fn disable_trust_dns(&mut self) -> &mut Self {
		self.config.disable_trust_dns();
		self
	}

	/// Returns if [`trust-dns`](trust_dns_resolver) is enabled.
	///
	/// See [`set_trust_dns`](Self::set_trust_dns) or
	/// [`disable_trust_dns`](Self::disable_trust_dns).
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	///
	/// builder.set_trust_dns(true);
	/// assert_eq!(builder.trust_dns(), true);
	///
	/// builder.disable_trust_dns();
	/// assert_eq!(builder.trust_dns(), false);
	/// ```
	#[must_use]
	pub const fn trust_dns(&self) -> bool {
		self.config.trust_dns()
	}

	/// Set's the default root certificate store. See [`Store`] for more
	/// details.
	///
	/// Default is [`Store::Embedded`].
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, Store};
	///
	/// let mut builder = Builder::new();
	/// builder.set_store(Store::Os);
	/// ```
	pub fn set_store(&mut self, store: Store) -> &mut Self {
		self.store = store;
		self
	}

	/// Returns the set [`Store`].
	///
	/// See [`set_store`](Self::set_store).
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, Store};
	///
	/// let mut builder = Builder::new();
	///
	/// // default
	/// assert_eq!(builder.store(), Store::Embedded);
	///
	/// builder.set_store(Store::Os);
	/// assert_eq!(builder.store(), Store::Os);
	///
	/// builder.set_store(Store::Empty);
	/// assert_eq!(builder.store(), Store::Empty);
	/// ```
	#[must_use]
	pub const fn store(&self) -> Store {
		self.store
	}

	/// Consumes [`Builder`] to build [`Endpoint`]. Must be called from inside
	/// the Tokio [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`error::Builder`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// - if the given [`KeyPair`]s or [`Certificate`]s are invalid - can't
	///   happen if they were properly validated through [`KeyPair::from_parts`]
	///   or [`Certificate::from_der`]
	/// - if not called from inside the Tokio
	///   [`Runtime`](tokio::runtime::Runtime)
	pub fn build(self) -> Result<Endpoint, error::Builder> {
		match {
			// build client
			let client = self.config.new_client(
				self.root_certificates.iter(),
				self.store,
				self.client_key_pair.clone(),
			);

			// build server only if we have a key-pair
			let server = self.server_key_pair.as_ref().map(|key_pair| {
				let mut server = ServerConfigBuilder::default();

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

				// set key-pair
				let chain = CertificateChain::from_certs(Some(key_pair.certificate().as_quinn()));
				let _ = server
					.certificate(chain, key_pair.private_key().as_quinn())
					.expect("`CertificateChain` couldn't be verified");

				// get inner rustls `ServerConfig`
				{
					let crypto =
						Arc::get_mut(&mut server.crypto).expect("failed to build `ServerConfig`");

					// set client certificate verifier
					crypto.set_client_certificate_verifier(Arc::new(ClientVerifier));
				}

				// set transport
				server.transport = self.config.transport();

				server
			});

			Endpoint::new(self.address, client, server, self.config.clone())
		} {
			Ok(endpoint) => Ok(endpoint),
			Err(error) => Err(error::Builder {
				error,
				builder: self,
			}),
		}
	}
}

/// Client certificate verifier accepting anything. Verification has to happen
/// on an application level.
struct ClientVerifier;

impl ClientCertVerifier for ClientVerifier {
	fn client_auth_mandatory(&self, _sni: Option<&DNSName>) -> Option<bool> {
		Some(false)
	}

	fn client_auth_root_subjects(&self, _sni: Option<&DNSName>) -> Option<DistinguishedNames> {
		Some(DistinguishedNames::new())
	}

	fn verify_client_cert(
		&self,
		_presented_certs: &[rustls::Certificate],
		_sni: Option<&DNSName>,
	) -> Result<ClientCertVerified, TLSError> {
		Ok(ClientCertVerified::assertion())
	}
}

/// Configuration option for [`Builder::set_store`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Store {
	/// Empty root certificate store.
	Empty,
	/// Uses the OS root certificate store, see
	/// [`rustls-native-certs`](https://docs.rs/rustls-native-certs).
	Os,
	/// Use an embedded root certificate store, see
	/// [`webpki-roots`](webpki_roots).
	Embedded,
}

/// Security-sensitive configuration for [`Builder`].
pub trait Dangerous {
	/// Adds a [`Certificate`] into the default certificate authority store for
	/// [`connection`](Endpoint::connect)ing to a server.
	///
	/// # Security
	/// Managing your own root certificate store can make sense if a private CA
	/// is used. Otherwise use [`Endpoint::connect_pinned`].
	fn add_ca(builder: &mut Self, certificate: Certificate);
}

impl Dangerous for Builder {
	fn add_ca(builder: &mut Self, certificate: Certificate) {
		builder.root_certificates.push(certificate);
	}
}

#[cfg(test)]
mod test {
	use anyhow::Result;
	use futures_util::StreamExt;

	use super::*;
	use crate::KeyPair;

	#[tokio::test]
	async fn default() -> Result<()> {
		let _endpoint = Builder::default().build()?;
		Ok(())
	}

	#[tokio::test]
	async fn new() -> Result<()> {
		let _endpoint = Builder::new().build()?;
		Ok(())
	}

	#[tokio::test]
	async fn address() -> Result<()> {
		let mut builder = Builder::new();
		let _ = builder.set_address(([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1], 5000).into());
		let endpoint = builder.build()?;

		assert_eq!(
			"[::ffff:127.0.0.1]:5000".parse::<SocketAddr>()?,
			endpoint.local_address()?,
		);

		Ok(())
	}

	#[tokio::test]
	async fn ca_key_pair() -> Result<()> {
		let key_pair = KeyPair::new_self_signed("localhost");

		// build client
		let mut builder = Builder::new();
		Dangerous::add_ca(&mut builder, key_pair.certificate().clone());
		let client = builder.build()?;

		// build server
		let mut builder = Builder::new();
		let _ = builder.set_server_key_pair(Some(key_pair));
		let mut server = builder.build()?;

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

	#[tokio::test]
	async fn client_certificate() -> Result<()> {
		let server_key_pair = KeyPair::new_self_signed("localhost");
		let client_key_pair = KeyPair::new_self_signed("client");

		// build client
		let mut builder = Builder::new();
		Dangerous::add_ca(&mut builder, server_key_pair.certificate().clone());
		let _ = builder.set_client_key_pair(Some(client_key_pair.clone()));
		let client = builder.build()?;

		// build server
		let mut builder = Builder::new();
		let _ = builder.set_server_key_pair(Some(server_key_pair));
		let mut server = builder.build()?;

		// test connection
		let _connection = client
			.connect(format!(
				"quic://localhost:{}",
				server.local_address()?.port()
			))
			.await?
			.accept::<()>()
			.await?;
		let connection = server
			.next()
			.await
			.expect("client dropped")
			.accept::<()>()
			.await?;

		// test client certificate
		assert_eq!(
			[client_key_pair.into_parts().0],
			connection
				.peer_identity()
				.expect("found no client certificate")
				.as_slice()
		);

		Ok(())
	}

	#[tokio::test]
	async fn protocols() -> Result<()> {
		let mut builder = Builder::new();
		let _ = builder.set_protocols([b"test".to_vec()]);
		let _endpoint = builder.build()?;

		Ok(())
	}
}
