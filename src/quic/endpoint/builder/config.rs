//! Persistent configuration shared between the [`Builder`](crate::Builder) and
//! the [`Endpoint`](crate::Endpoint).

use std::{ops::Deref, sync::Arc};

use quinn::{ClientConfig, ClientConfigBuilder, TransportConfig};
use rustls::{sign::CertifiedKey, ResolvesClientCert, RootCertStore, SignatureScheme};

use crate::{Certificate, PrivateKey, Store};

/// Persistent configuration shared between the [`Builder`](crate::Builder) and
/// the [`Endpoint`](crate::Endpoint).
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
}

impl Config {
	/// Builds a new [`Config`].
	pub(super) fn new() -> Self {
		// build transport
		let mut transport = TransportConfig::default();

		// set transport defaults
		let _ = transport
			// TODO: research if this is necessary, it improves privacy, but may hurt network
			// providers?
			.allow_spin(false)
			// we don't support unordered for now
			.datagram_receive_buffer_size(None)
			// TODO: handle uni streams
			.max_concurrent_uni_streams(0)
			.expect("can't be bigger then `VarInt`");

		let transport = Arc::new(transport);

		Self {
			transport,
			protocols: Vec::new(),
			#[cfg(feature = "trust-dns")]
			trust_dns: true,
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

	/// Returns the configured protocols.
	pub(super) const fn protocols(&self) -> &Vec<Vec<u8>> {
		&self.protocols
	}

	/// Forces [`Endpoint::connect`](crate::Endpoint::connect) to use
	/// [`trust-dns`](trust_dns_resolver).
	#[cfg_attr(
		not(feature = "trust-dns"),
		allow(clippy::unused_self, unused_variables)
	)]
	pub(super) fn set_trust_dns(&mut self, trust_dns: bool) {
		#[cfg(feature = "trust-dns")]
		{
			self.trust_dns = trust_dns;
		}
	}

	/// Returns if [`trust-dns`](trust_dns_resolver) is enabled.
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub(in crate::quic::endpoint) const fn trust_dns(&self) -> bool {
		self.trust_dns
	}

	/// Builds a new [`ClientConfig`] with this [`Config`] and adds
	/// `certificates` to the CA store.
	///
	/// # Panics
	/// Panics if the given [`Certificate`] is invalid. Can't happen if the
	/// [`Certificate`] was properly validated through
	/// [`Certificate::from_der`].
	pub(in crate::quic::endpoint) fn new_client<'a>(
		&self,
		certificates: impl IntoIterator<Item = &'a Certificate> + 'a,
		store: Store,
		client_cert: Option<(Certificate, PrivateKey)>,
	) -> ClientConfig {
		// build client
		let mut client = ClientConfig::default();

		// get inner rustls `ClientConfig`
		let crypto = Arc::get_mut(&mut client.crypto).expect("failed to build `ClientConfig`");

		match store {
			// remove the defaults set by Quinn
			Store::Empty => {
				crypto.root_store = RootCertStore::empty();
				crypto.ct_logs = None;
			}
			// is set correctly by Quinn by default
			Store::Os => (),
			Store::Embedded => {
				let mut store = RootCertStore::empty();
				store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
				crypto.root_store = store;
			}
		}

		if let Some((certificate, private_key)) = client_cert {
			crypto.client_auth_cert_resolver = CertificateResolver::new(certificate, private_key);
		}

		// build client builder
		let mut client = ClientConfigBuilder::new(client);

		// add protocols
		if !self.protocols.is_empty() {
			let protocols: Vec<_> = self.protocols.iter().map(Deref::deref).collect();
			let _ = client.protocols(&protocols);
		}

		// add CAs
		for certificate in certificates {
			let _ = client
				.add_certificate_authority(certificate.as_quinn())
				.expect("`Certificate` couldn't be added as a CA");
		}

		let mut client = client.build();
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
	fn new(certificate: Certificate, private_key: PrivateKey) -> Arc<Self> {
		Arc::new(Self(CertifiedKey::new(
			vec![certificate.into_rustls()],
			#[allow(box_pointers)]
			Arc::new(private_key.into_rustls()),
		)))
	}
}
