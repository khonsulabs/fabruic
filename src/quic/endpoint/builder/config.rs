//! Persistent configuration shared between [`Builder`](crate::Builder) and
//! [`Endpoint`](crate::Endpoint).

use std::{sync::Arc, time::SystemTime};

use quinn::{ClientConfig, TransportConfig};
use rustls::{
	client::{
		CertificateTransparencyPolicy, ResolvesClientCert, ServerCertVerified, ServerCertVerifier,
		WebPkiVerifier,
	},
	sign::CertifiedKey,
	OwnedTrustAnchor, RootCertStore, ServerName, SignatureScheme,
};
use time::{Date, Month, PrimitiveDateTime, Time};
use webpki::TrustAnchor;

use crate::{
	error::{self, OsStore},
	Certificate, KeyPair, Store,
};

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
			.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));

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
	#[allow(clippy::unwrap_in_result)]
	pub(in crate::quic::endpoint) fn new_client(
		&self,
		certificates: &[Certificate],
		store: Store,
		client_key_pair: Option<KeyPair>,
		disable_server_verification: bool,
	) -> Result<ClientConfig, OsStore> {
		// disable server certificate verification if demanded
		let server_verifier: Arc<dyn ServerCertVerifier> = if disable_server_verification {
			NoServerCertVerification::new()
		} else {
			// set default root certificates
			let mut root_store = match store {
				Store::Empty => RootCertStore::empty(),
				Store::Os => {
					let mut store = RootCertStore::empty();

					store.roots = rustls_native_certs::load_native_certs()
						.map_err(error::OsStore::Aquire)?
						.into_iter()
						.map(|certificate| {
							let ta = TrustAnchor::try_from_cert_der(&certificate.0)
								.map_err(error::OsStore::Parse)?;

							Ok(OwnedTrustAnchor::from_subject_spki_name_constraints(
								ta.subject,
								ta.spki,
								ta.name_constraints,
							))
						})
						.collect::<Result<_, _>>()?;

					store
				}
				Store::Embedded => {
					let mut store = RootCertStore::empty();

					store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
						|ta| {
							OwnedTrustAnchor::from_subject_spki_name_constraints(
								ta.subject,
								ta.spki,
								ta.name_constraints,
							)
						},
					));

					store
				}
			};

			// add custom root certificates
			let additional_anchors = certificates.iter().map(|certificate| {
				let anchor = TrustAnchor::try_from_cert_der(certificate.as_ref())
					.expect("`Certificate` couldn't be parsed");
				OwnedTrustAnchor::from_subject_spki_name_constraints(
					anchor.subject,
					anchor.spki,
					anchor.name_constraints,
				)
			});
			root_store.add_server_trust_anchors(additional_anchors);

			// Add certificate transparency logs
			// TODO: configuratbility
			let ct_policy = match store {
				Store::Empty => None,
				Store::Os | Store::Embedded => Some(CertificateTransparencyPolicy::new(
					ct_logs::LOGS,
					// Add one year to last release.
					PrimitiveDateTime::new(
						#[allow(clippy::integer_arithmetic)]
						Date::from_calendar_date(2021 + 1, Month::April, 10).expect("invalid date"),
						Time::MIDNIGHT,
					)
					.assume_utc()
					.into(),
				)),
			};

			Arc::new(WebPkiVerifier::new(root_store, ct_policy))
		};

		let crypto = rustls::ClientConfig::builder()
			.with_safe_default_cipher_suites()
			.with_safe_default_kx_groups()
			.with_protocol_versions(&[&rustls::version::TLS13])
			.expect("failed to configure correct protocol")
			.with_custom_certificate_verifier(server_verifier);

		let mut crypto = if let Some(key_pair) = client_key_pair {
			crypto.with_client_cert_resolver(CertificateResolver::new(key_pair))
		} else {
			crypto.with_no_client_auth()
		};

		crypto.enable_early_data = true;
		crypto.alpn_protocols = self.protocols.clone();

		let mut client = ClientConfig::new(Arc::new(crypto));
		client.transport = self.transport();

		Ok(client)
	}
}

/// Client certificate handler.
struct CertificateResolver(Arc<CertifiedKey>);

impl ResolvesClientCert for CertificateResolver {
	fn resolve(
		&self,
		_acceptable_issuers: &[&[u8]],
		_sigschemes: &[SignatureScheme],
	) -> Option<Arc<CertifiedKey>> {
		Some(Arc::clone(&self.0))
	}

	fn has_certs(&self) -> bool {
		true
	}
}

impl CertificateResolver {
	/// Builds a new [`CertificateResolver`].
	fn new(key_pair: KeyPair) -> Arc<Self> {
		Arc::new(Self(Arc::new(key_pair.into_rustls())))
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
		_end_entity: &rustls::Certificate,
		_intermediates: &[rustls::Certificate],
		_server_name: &ServerName,
		_scts: &mut dyn Iterator<Item = &[u8]>,
		_ocsp_response: &[u8],
		_now: SystemTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}
}

impl NoServerCertVerification {
	/// Builds a new [`NoServerCertVerification`].
	fn new() -> Arc<Self> {
		Arc::new(Self)
	}
}
