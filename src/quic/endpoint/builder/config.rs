//! Persistent configuration shared between [`Builder`](crate::Builder) and
//! [`Endpoint`](crate::Endpoint).

use std::{ops::Deref, sync::Arc};

use quinn::{ClientConfig, ClientConfigBuilder, TransportConfig};
use rustls::{
	sign::CertifiedKey, OwnedTrustAnchor, ResolvesClientCert, RootCertStore, ServerCertVerified,
	ServerCertVerifier, SignatureScheme, TLSError,
};
use webpki::{trust_anchor_util, DNSNameRef};

use crate::{Certificate, KeyPair, Store};

/// Persistent configuration shared between [`Builder`](crate::Builder) and
/// [`Endpoint`](crate::Endpoint).
#[derive(Clone, Debug)]
pub(in crate::quic::endpoint) struct Config {
	/// Storing the default [`TransportConfig`].
	transport: Arc<TransportConfig>,
	/// Protocols used.
	protocols: Vec<Vec<u8>>,
	/// Enable [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	trust_dns: bool,
	/// Enables DNSSEC validation for [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	dnssec: bool,
	/// Enables `/etc/hosts` file support for [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	hosts_file: bool,
}

impl Config {
	/// Builds a new [`Config`].
	pub(super) fn new() -> Self {
		let mut transport = TransportConfig::default();

		// set transport defaults
		// TODO: research other settings
		let _ = transport
			// TODO: research if this is necessary, it improves privacy, but may hurt network
			// providers?
			.allow_spin(false)
			// we don't support unordered for now
			.datagram_receive_buffer_size(None)
			// for compatibility with WebRTC, we won't be using uni-directional streams
			.max_concurrent_uni_streams(0)
			.expect("can't be bigger then `VarInt`");

		Self {
			transport: Arc::new(transport),
			protocols: Vec::new(),
			#[cfg(feature = "trust-dns")]
			trust_dns: true,
			#[cfg(feature = "trust-dns")]
			dnssec: true,
			#[cfg(feature = "trust-dns")]
			hosts_file: false,
		}
	}

	/// Returns the default [`TransportConfig`].
	pub(super) fn transport(&self) -> Arc<TransportConfig> {
		Arc::clone(&self.transport)
	}

	/// Set the application-layer protocols.
	pub(super) fn set_protocols(&mut self, protocols: impl Into<Vec<Vec<u8>>>) {
		self.protocols = protocols.into();
	}

	/// Returns the configured application-layer protocols.
	pub(super) fn protocols(&self) -> &[Vec<u8>] {
		self.protocols.as_slice()
	}

	/// Controls the use of [`trust-dns`](trust_dns_resolver) for
	/// [`Endpoint::connect`](crate::Endpoint::connect).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub(super) fn set_trust_dns(&mut self, enable: bool) {
		self.trust_dns = enable;
	}

	/// Disables the use of [`trust-dns`](trust_dns_resolver) for
	/// [`Endpoint::connect`](crate::Endpoint::connect) despite the activates
	/// crate features.
	#[cfg_attr(
		not(feature = "trust-dns"),
		allow(clippy::unused_self, unused_variables)
	)]
	pub(super) fn disable_trust_dns(&mut self) {
		#[cfg(feature = "trust-dns")]
		{
			self.trust_dns = false;
		}
	}

	/// Returns if [`trust-dns`](trust_dns_resolver) is enabled.
	pub(in crate::quic::endpoint) const fn trust_dns(&self) -> bool {
		#[cfg(feature = "trust-dns")]
		return self.trust_dns;
		#[cfg(not(feature = "trust-dns"))]
		false
	}

	/// Controls DNSSEC validation for [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub(super) fn set_dnssec(&mut self, enable: bool) {
		self.dnssec = enable;
	}

	/// Returns if DNSSEC is enabled for [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub(in crate::quic::endpoint) const fn dnssec(&self) -> bool {
		self.dnssec
	}

	/// Controls `/etc/hosts` file support for
	/// [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub(super) fn set_hosts_file(&mut self, enable: bool) {
		self.hosts_file = enable;
	}

	/// Returns if `/etc/hosts` file support is enabled for
	/// [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub(in crate::quic::endpoint) const fn hosts_file(&self) -> bool {
		self.hosts_file
	}

	/// Builds a new [`ClientConfig`] with this [`Config`] and adds
	/// [`Certificate`]s to the CA store.
	///
	/// # Panics
	/// Panics if the given [`KeyPair`] or [`Certificate`]s are invalid. Can't
	/// happen if they were properly validated through [`KeyPair::from_parts`]
	/// or [`Certificate::from_der`].
	pub(in crate::quic::endpoint) fn new_client<'a>(
		&self,
		certificates: impl IntoIterator<Item = &'a Certificate> + 'a,
		store: Store,
		client_key_pair: Option<KeyPair>,
		disable_server_verification: bool,
	) -> ClientConfig {
		let mut client = ClientConfigBuilder::default();

		// add protocols
		if !self.protocols.is_empty() {
			let protocols: Vec<_> = self.protocols.iter().map(Deref::deref).collect();
			let _ = client.protocols(&protocols);
		}

		let mut client = client.build();

		// get inner rustls `ClientConfig`
		{
			let crypto = Arc::get_mut(&mut client.crypto).expect("failed to build `ClientConfig`");

			// set default root certificates
			match store {
				// remove the defaults set by Quinn
				Store::Empty => {
					crypto.root_store = RootCertStore::empty();
					crypto.ct_logs = None;
				}
				// is set correctly by Quinn by default
				Store::Os => (),
				// insert `webpki-roots`
				Store::Embedded => {
					let mut store = RootCertStore::empty();
					store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
					crypto.root_store = store;
				}
			}

			// add custom root certificates
			let certificates = certificates.into_iter().map(|certificate| {
				let anchor = trust_anchor_util::cert_der_as_trust_anchor(certificate.as_ref())
					.expect("`Certificate` couldn't be parsed");
				OwnedTrustAnchor::from_trust_anchor(&anchor)
			});
			crypto.root_store.roots.extend(certificates);

			// insert client certificate
			if let Some(key_pair) = client_key_pair {
				crypto.client_auth_cert_resolver = CertificateResolver::new(key_pair);
			}

			// disable server certificate verification if demanded
			if disable_server_verification {
				crypto
					.dangerous()
					.set_certificate_verifier(NoServerCertVerification::new());
			}
		}

		// set transport
		client.transport = self.transport();

		client
	}
}

/// Client certificate handler.
struct CertificateResolver(CertifiedKey);

impl ResolvesClientCert for CertificateResolver {
	fn resolve(
		&self,
		_acceptable_issuers: &[&[u8]],
		_sigschemes: &[SignatureScheme],
	) -> Option<CertifiedKey> {
		Some(self.0.clone())
	}

	fn has_certs(&self) -> bool {
		true
	}
}

impl CertificateResolver {
	/// Builds a new [`CertificateResolver`].
	fn new(key_pair: KeyPair) -> Arc<Self> {
		Arc::new(Self(key_pair.into_rustls()))
	}
}

/// Disables clients verification of the servers [`Certificate`] when used with
/// [`Endpoint::connect_unverified`].
///
/// [`Endpoint::connect_unverified`]:
/// crate::dangerous::Endpoint::connect_unverified
struct NoServerCertVerification;

impl ServerCertVerifier for NoServerCertVerification {
	fn verify_server_cert(
		&self,
		_: &RootCertStore,
		_: &[rustls::Certificate],
		_: DNSNameRef<'_>,
		_: &[u8],
	) -> Result<ServerCertVerified, TLSError> {
		Ok(ServerCertVerified::assertion())
	}
}

impl NoServerCertVerification {
	/// Builds a new [`NoServerCertVerification`].
	fn new() -> Arc<Self> {
		Arc::new(Self)
	}
}
