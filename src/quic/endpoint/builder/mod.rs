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
/// builder.set_protocols([b"test".to_vec()]);
/// builder.set_store(Store::Os);
/// let endpoint = builder.build()?;
/// # Ok(()) }
/// ```
#[must_use = "doesn't do anything unless `Builder::build` is called"]
#[derive(Debug)]
pub struct Builder {
	/// [`SocketAddr`] for [`Endpoint`](quinn::Endpoint) to bind to.
	address: SocketAddr,
	/// Custom root [`Certificate`]s.
	root_certificates: Vec<Certificate>,
	/// Server certificate key-pair.
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
	pub fn new() -> Self {
		let config = Config::new();

		Self {
			#[cfg(not(feature = "test"))]
			address: ([0; 8], 0).into(),
			// while testing always use the default loopback address
			#[cfg(feature = "test")]
			address: ([0, 0, 0, 0, 0, 0, 0, 1], 0).into(),
			root_certificates: Vec::new(),
			server_key_pair: None,
			client_key_pair: None,
			store: Store::Embedded,
			config,
		}
	}

	/// Set's the [`SocketAddr`] to bind to.
	///
	/// # Default
	/// `[::\]:0`.
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
	pub fn set_address(&mut self, address: SocketAddr) {
		self.address = address;
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
	/// # Default
	/// [`None`].
	///
	/// # Notes
	/// [`Endpoint`] won't listen to any incoming
	/// [`Connection`](crate::Connection)s without a server certificate.
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, KeyPair};
	///
	/// let mut builder = Builder::new();
	/// builder.set_server_key_pair(Some(KeyPair::new_self_signed("test")));
	/// ```
	pub fn set_server_key_pair(&mut self, key_pair: Option<KeyPair>) {
		self.server_key_pair = key_pair;
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
	/// # Default
	/// [`None`].
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, KeyPair};
	///
	/// let mut builder = Builder::new();
	/// builder.set_client_key_pair(Some(KeyPair::new_self_signed("test")));
	/// ```
	pub fn set_client_key_pair(&mut self, key_pair: Option<KeyPair>) {
		self.client_key_pair = key_pair;
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
	/// # Default
	/// No protocols.
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	/// builder.set_protocols([b"test".to_vec()]);
	/// ```
	pub fn set_protocols<P: Into<Vec<Vec<u8>>>>(&mut self, protocols: P) {
		self.config.set_protocols(protocols);
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
	/// # Default
	/// [`true`] if the crate feature <span
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
	pub fn set_trust_dns(&mut self, enable: bool) {
		self.config.set_trust_dns(enable);
	}

	/// Disables the use of [`trust-dns`](trust_dns_resolver) for
	/// [`Endpoint::connect`] despite the activated crate feature.
	///
	/// # Default
	/// Not disabled if the crate feature <span
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
	pub fn disable_trust_dns(&mut self) {
		self.config.disable_trust_dns();
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

	/// Controls DNSSEC validation for [`trust-dns`](trust_dns_resolver) in
	/// [`Endpoint::connect`]. This doesn't affect the
	/// [`ToSocketAddrs`](std::net::ToSocketAddrs) resolver.
	///
	/// # Default
	/// [`true`].
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	/// builder.set_dnssec(false);
	/// ```
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub fn set_dnssec(&mut self, enable: bool) {
		self.config.set_dnssec(enable);
	}

	/// Returns if DNSSEC is enabled for [`trust-dns`](trust_dns_resolver).
	///
	/// See [`set_dnssec`](Self::set_dnssec).
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	///
	/// builder.set_dnssec(false);
	/// assert_eq!(builder.dnssec(), false);
	/// ```
	#[must_use]
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub const fn dnssec(&self) -> bool {
		self.config.dnssec()
	}

	/// Controls `/etc/hosts` file support for [`trust-dns`](trust_dns_resolver)
	/// in [`Endpoint::connect`]. This doesn't affect the
	/// [`ToSocketAddrs`](std::net::ToSocketAddrs) resolver.
	///
	/// # Default
	/// [`false`]. Only affects UNIX like OS's.
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	/// builder.set_hosts_file(false);
	/// ```
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub fn set_hosts_file(&mut self, enable: bool) {
		self.config.set_hosts_file(enable);
	}

	/// Returns if `/etc/hosts` file support is enabled for
	/// [`trust-dns`](trust_dns_resolver).
	///
	/// See [`set_dnssec`](Self::set_hosts_file).
	///
	/// # Examples
	/// ```
	/// use fabruic::Builder;
	///
	/// let mut builder = Builder::new();
	///
	/// builder.set_hosts_file(true);
	/// assert_eq!(builder.hosts_file(), true);
	/// ```
	#[must_use]
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub const fn hosts_file(&self) -> bool {
		self.config.hosts_file()
	}

	/// Set's the default root certificate store.
	///
	/// See [`Store`] for more details.
	///
	/// # Default
	/// [`Store::Embedded`].
	///
	/// # Examples
	/// ```
	/// use fabruic::{Builder, Store};
	///
	/// let mut builder = Builder::new();
	/// builder.set_store(Store::Os);
	/// ```
	pub fn set_store(&mut self, store: Store) {
		self.store = store;
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
	pub const fn store(&self) -> Store {
		self.store
	}

	/// Consumes [`Builder`] to build [`Endpoint`]. Must be called from inside a
	/// Tokio [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`error::Builder`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// - if the given [`KeyPair`]s or [`Certificate`]s are invalid - can't
	///   happen if they were properly validated through [`KeyPair::from_parts`]
	///   or [`Certificate::from_der`]
	/// - if not called from inside a Tokio [`Runtime`](tokio::runtime::Runtime)
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Builder;
	///
	/// let endpoint = Builder::new().build()?;
	/// # Ok(()) }
	/// ```
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
///
/// # Examples
/// ```
/// use fabruic::{Builder, Store};
///
/// let mut builder = Builder::new();
/// builder.set_store(Store::Os);
/// ```
#[must_use = "doesn't do anything unless passed into `Builder::set_store`"]
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
	/// Set [`Certificate`]s to be added into the root certificate store for
	/// [`connect`](Endpoint::connect)ing to a server. This is added
	/// additionally to the [`Store`] root certificates and does **not** replace
	/// them.
	///
	/// See [`Builder::set_store`].
	///
	/// # Security
	/// Managing your own root certificate store can make sense if a private CA
	/// is used. Otherwise use [`Endpoint::connect_pinned`].
	///
	/// # Examples
	/// ```
	/// use fabruic::{dangerous, Builder, Store};
	///
	/// let mut builder = Builder::new();
	/// builder.set_store(Store::Empty);
	/// // CA certificate has to be imported from somewhere else
	/// # let (ca_certificate, _) = fabruic::KeyPair::new_self_signed("test").into_parts();
	/// dangerous::Builder::set_root_certificates(&mut builder, [ca_certificate]);
	/// ```
	fn set_root_certificates<C: Into<Vec<Certificate>>>(builder: &mut Self, certificates: C);
}

impl Dangerous for Builder {
	fn set_root_certificates<C: Into<Vec<Certificate>>>(builder: &mut Self, certificates: C) {
		builder.root_certificates = certificates.into();
	}
}

#[cfg(test)]
mod test {
	use std::task::Poll;

	use anyhow::Result;
	use futures_util::StreamExt;
	use quinn::{ConnectionClose, ConnectionError};
	use quinn_proto::TransportError;
	use trust_dns_proto::error::ProtoErrorKind;
	use trust_dns_resolver::error::ResolveErrorKind;

	use super::*;

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

		let address = ([0, 0, 0, 0, 0, 0, 0, 1], 5000).into();
		builder.set_address(address);
		assert_eq!(builder.address(), &address);

		let endpoint = builder.build()?;
		assert_eq!(endpoint.local_address()?, address);

		Ok(())
	}

	#[tokio::test]
	async fn server_certificate() -> Result<()> {
		let key_pair = KeyPair::new_self_signed("localhost");

		// build client
		let client = Builder::new().build()?;

		// build server
		let mut builder = Builder::new();
		builder.set_server_key_pair(Some(key_pair.clone()));
		let mut server = builder.build()?;

		// test connection to server
		let _connection = client
			.connect_pinned(
				format!("quic://{}", server.local_address()?),
				key_pair.certificate(),
				None,
			)
			.await?
			.accept::<()>()
			.await?;

		// test receiving client on server
		let _connection = server
			.next()
			.await
			.expect("server dropped")
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
		Dangerous::set_root_certificates(&mut builder, [server_key_pair.certificate().clone()]);
		builder.set_client_key_pair(Some(client_key_pair.clone()));
		let client = builder.build()?;

		// build server
		let mut builder = Builder::new();
		builder.set_server_key_pair(Some(server_key_pair));
		let mut server = builder.build()?;

		// test connection to server
		let _connection = client
			.connect(format!(
				"quic://localhost:{}",
				server.local_address()?.port()
			))
			.await?
			.accept::<()>()
			.await?;

		// test receiving client on server
		let connection = server
			.next()
			.await
			.expect("server dropped")
			.accept::<()>()
			.await?;

		// validate client certificate
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

		let protocols = [b"test".to_vec()];
		builder.set_protocols(protocols.clone());
		assert_eq!(builder.protocols(), protocols);

		let _endpoint = builder.build()?;

		Ok(())
	}

	#[tokio::test]
	async fn protocols_compatible() -> Result<()> {
		let key_pair = KeyPair::new_self_signed("test");
		let protocols = [b"test".to_vec()];

		// build client
		let mut builder = Builder::new();
		builder.set_protocols(protocols.clone());
		let client = builder.build()?;

		// build server
		let mut builder = Builder::new();
		builder.set_server_key_pair(Some(key_pair.clone()));
		builder.set_protocols(protocols.clone());
		let mut server = builder.build()?;

		// connect with server
		let mut connecting = client
			.connect_pinned(
				format!("quic://{}", server.local_address()?),
				key_pair.certificate(),
				None,
			)
			.await?;

		// check protocol on `Connecting`
		assert_eq!(
			protocols[0],
			connecting.protocol().await?.expect("no protocol found")
		);

		// check protocol on `Connection`
		let connection = connecting.accept::<()>().await?;
		assert_eq!(
			protocols[0],
			connection.protocol().expect("no protocol found")
		);

		// receive connection from client
		let mut connecting = server.next().await.expect("server dropped");

		// check protocol on `Connecting`
		assert_eq!(
			protocols[0],
			connecting.protocol().await?.expect("no protocol found")
		);

		// check protocol on `Connection`
		let connection = connecting.accept::<()>().await?;
		assert_eq!(
			protocols[0],
			connection.protocol().expect("no protocol found")
		);

		Ok(())
	}

	#[tokio::test]
	async fn protocols_incompatible() -> Result<()> {
		let key_pair = KeyPair::new_self_signed("test");

		// build client
		let mut builder = Builder::new();
		builder.set_protocols([b"test1".to_vec()]);
		let client = builder.build()?;

		// build server
		let mut builder = Builder::new();
		builder.set_server_key_pair(Some(key_pair.clone()));
		builder.set_protocols([b"test2".to_vec()]);
		let mut server = builder.build()?;

		// connect with server
		let result = client
			.connect_pinned(
				format!("quic://{}", server.local_address()?),
				key_pair.certificate(),
				None,
			)
			.await?
			.accept::<()>()
			.await;

		// check result
		assert!(matches!(
			result,
			Err(error::Connecting(ConnectionError::ConnectionClosed(ConnectionClose {
				error_code,
				frame_type: None,
				reason
			}))) if (reason.as_ref() == b"peer doesn't support any known protocol")
				&& error_code.to_string() == "the cryptographic handshake failed: error 120"));

		// on protocol mismatch, the server receives nothing
		assert!(matches!(
			allochronic_util::poll(server.next()).await,
			Poll::Pending
		));

		Ok(())
	}

	#[test]
	fn trust_dns() {
		let mut builder = Builder::new();

		// default
		assert!(builder.trust_dns());

		builder.set_trust_dns(false);
		assert!(!builder.trust_dns());

		builder.set_trust_dns(true);
		assert!(builder.trust_dns());

		builder.disable_trust_dns();
		assert!(!builder.trust_dns());
	}

	#[tokio::test]
	async fn trust_dns_disabled() -> Result<()> {
		let mut builder = Builder::new();
		builder.disable_trust_dns();
		let endpoint = builder.build()?;

		// TODO: find a better target without DNSSEC support then Google
		assert!(endpoint.connect("https://google.com").await.is_ok());

		Ok(())
	}

	#[tokio::test]
	async fn trust_dns_success() -> Result<()> {
		let mut builder = Builder::new();
		builder.disable_trust_dns();
		let endpoint = builder.build()?;

		// TODO: find a better target with DNSSEC support then Cloudflare
		assert!(endpoint.connect("https://cloudflare.com").await.is_ok());

		Ok(())
	}

	#[tokio::test]
	async fn trust_dns_fail() -> Result<()> {
		let endpoint = Builder::new().build()?;

		// TODO: find a better target without DNSSEC support then Google
		let result = endpoint.connect("https://google.com").await;

		// target has no DNSSEC records
		if let Err(error::Connect::TrustDns(error)) = &result {
			if let ResolveErrorKind::Proto(error) = error.kind() {
				if let ProtoErrorKind::RrsigsNotPresent { .. } = error.kind() {
					return Ok(());
				}
			}
		}

		// any other error or `Ok` should fail the test
		panic!("unexpected result: {:?}", result)
	}

	#[test]
	fn dnssec() {
		let mut builder = Builder::new();

		// default
		assert!(builder.dnssec());

		builder.set_dnssec(false);
		assert!(!builder.dnssec());

		builder.set_dnssec(true);
		assert!(builder.dnssec());
	}

	#[tokio::test]
	async fn dnssec_disabled() -> Result<()> {
		let mut builder = Builder::new();
		builder.set_dnssec(false);
		let endpoint = builder.build()?;

		// TODO: find a better target without DNSSEC support then Google
		assert!(endpoint.connect("https://google.com").await.is_ok());

		Ok(())
	}

	#[test]
	fn hosts_file() {
		let mut builder = Builder::new();

		// default
		assert!(!builder.hosts_file());

		builder.set_hosts_file(true);
		assert!(builder.hosts_file());

		builder.set_hosts_file(false);
		assert!(!builder.hosts_file());
	}

	#[tokio::test]
	async fn store_embedded() -> Result<()> {
		let mut builder = Builder::new();
		// `cfg(test)` will use `[::1]` by default, but we need to do an outgoing
		// connection
		builder.set_address(([0; 8], 0).into());
		// QUIC is comptaible with HTTP/3 to establish a connection only
		builder.set_protocols([b"h3-29".to_vec()]);
		// `cloudflare-quic` doesn't support DNSSEC
		builder.set_dnssec(false);

		// default
		assert_eq!(builder.store(), Store::Embedded);

		builder.set_store(Store::Embedded);
		assert_eq!(builder.store(), Store::Embedded);

		let endpoint = builder.build()?;

		// TODO: find a better target to test our root certificate store against
		assert!(endpoint
			.connect("https://cloudflare-quic.com:443")
			.await?
			.accept::<()>()
			.await
			.is_ok());

		Ok(())
	}

	#[tokio::test]
	async fn store_os() -> Result<()> {
		let mut builder = Builder::new();
		// `cfg(test)` will use `[::1]` by default, but we need to do an outgoing
		// connection
		builder.set_address(([0; 8], 0).into());
		// QUIC is comptaible with HTTP/3 to establish a connection only
		builder.set_protocols([b"h3-29".to_vec()]);
		// `cloudflare-quic` doesn't support DNSSEC
		builder.set_dnssec(false);

		builder.set_store(Store::Os);
		assert_eq!(builder.store(), Store::Os);

		let endpoint = builder.build()?;

		// TODO: find a better target to test our root certificate store against
		assert!(endpoint
			.connect("https://cloudflare-quic.com:443")
			.await?
			.accept::<()>()
			.await
			.is_ok());

		Ok(())
	}

	#[tokio::test]
	async fn store_empty() -> Result<()> {
		let mut builder = Builder::new();
		// `cfg(test)` will use `[::1]` by default, but we need to do an outgoing
		// connection
		builder.set_address(([0; 8], 0).into());
		// QUIC is comptaible with HTTP/3 to establish a connection only
		builder.set_protocols([b"h3-29".to_vec()]);
		// `cloudflare-quic` doesn't support DNSSEC
		builder.set_dnssec(false);

		builder.set_store(Store::Empty);
		assert_eq!(builder.store(), Store::Empty);

		let endpoint = builder.build()?;

		// TODO: find a better target to test our root certificate store against
		let result = endpoint
			.connect("https://cloudflare-quic.com:443")
			.await?
			.accept::<()>()
			.await;

		// check result
		assert!(matches!(
				result,
				Err(error::Connecting(ConnectionError::TransportError(TransportError {
					code,
					frame: None,
					reason
				}))) if (reason == "invalid certificate: UnknownIssuer")
					&& code.to_string() == "the cryptographic handshake failed: error 42"));

		Ok(())
	}
}
