//! [`Certificate`].

use std::time::Duration;

use error::CertificateError;
use serde::{Deserialize, Serialize};
use webpki::EndEntityCert;
use x509_parser::{certificate::X509Certificate, extensions::GeneralName, prelude::FromDer};

use crate::error;

/// A public certificate. You can distribute it freely to peers.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Certificate(Vec<u8>);

impl AsRef<[u8]> for Certificate {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl From<Certificate> for Vec<u8> {
	fn from(certificate: Certificate) -> Self {
		certificate.0
	}
}

impl TryFrom<Vec<u8>> for Certificate {
	type Error = error::Certificate;

	fn try_from(certificate: Vec<u8>) -> Result<Self, Self::Error> {
		Self::from_der(certificate)
	}
}

impl Certificate {
	/// Build [`Certificate`] from DER-format. This is not meant as a full
	/// validation of a [`Certificate`], it just offers some sane protections.
	///
	/// # Errors
	/// - [`CertificateError::WebPki`] or [`CertificateError::X509`] if the
	///   certificate couldn't be parsed
	/// - [`CertificateError::Dangling`] if the certificate contained
	///   uncorrelated bytes
	/// - [`CertificateError::Expired`] if the certificate has expires
	/// - [`CertificateError::Domain`] if the certificate doesn't contain a
	///   domain name
	pub fn from_der<C: Into<Vec<u8>>>(certificate: C) -> Result<Self, error::Certificate> {
		let certificate = certificate.into();

		// parse certificate with `webpki`, which is what `rustls` uses, which is what
		// `quinn` uses
		let _ = match EndEntityCert::try_from(certificate.as_slice()) {
			Ok(parsed) => parsed,
			Err(error) =>
				return Err(error::Certificate {
					error: CertificateError::WebPki(error),
					certificate,
				}),
		};

		// parse certificate with the `x509-parser, which is what `rcgen` uses
		let (trailing, parsed) = match X509Certificate::from_der(&certificate) {
			Ok((trailing, bytes)) => (trailing, bytes),
			Err(error) =>
				return Err(error::Certificate {
					error: CertificateError::X509(error),
					certificate,
				}),
		};

		// don't allow trailing bytes
		if !trailing.is_empty() {
			return Err(error::Certificate {
				error: CertificateError::Dangling(trailing.to_owned()),
				certificate,
			});
		}

		// check certificates validity
		if let Some(duration) = parsed.validity().time_to_expiration() {
			// check if the certificate is going to expire in 20 days, which is the default
			// for Let's Encrypt to send a warning:
			// <https://letsencrypt.org/docs/expiration-emails/#subscribing>
			if duration <= Duration::from_secs(1_728_000) {
				// TODO: log warning that it will expire
			}
		} else {
			return Err(error::Certificate {
				error: CertificateError::Expired,
				certificate,
			});
		}

		// certificate has to include domain names
		if parsed
			.tbs_certificate
			.subject_alternative_name()
			.ok()
			.flatten()
			.filter(|name| !name.value.general_names.is_empty())
			.is_none()
		{
			return Err(error::Certificate {
				error: CertificateError::Domain,
				certificate,
			});
		}

		// TODO: extend validation to use something like
		// `webpki::EndEntityCert::verify_is_valid_tls_client_cert`

		Ok(Self(certificate))
	}

	/// Build [`Certificate`] from DER-format. This skips the validation from
	/// [`from_der`](Self::from_der), which isn't `unsafe`, but could fail
	/// nonetheless when used on an [`Endpoint`](crate::Endpoint).
	#[must_use]
	pub fn unchecked_from_der<C: Into<Vec<u8>>>(certificate: C) -> Self {
		Self(certificate.into())
	}

	/// # Panics
	/// Panics if [`Certificate`] couldn't be parsed or contained no valid
	/// domain names. This can't happen if [`Certificate`] is constructed
	/// correctly from [`from_der`](Self::from_der).
	#[must_use]
	pub fn domains(&self) -> Vec<String> {
		let (_, certificate) =
			X509Certificate::from_der(&self.0).expect("`Certificate` couldn't be parsed");

		certificate
			.tbs_certificate
			.subject_alternative_name()
			.ok()
			.flatten()
			.map(|name| {
				name.value
					.general_names
					.iter()
					.filter_map(|name| {
						if let GeneralName::DNSName(name) = name {
							Some((*name).to_owned())
						} else {
							None
						}
					})
					.collect()
			})
			.expect("`Certificate` contained no valid domains")
	}

	/// Convert from a [`rustls`] type.
	pub(crate) fn from_rustls(certificate: rustls::Certificate) -> Self {
		Self::unchecked_from_der(certificate.0)
	}

	/// Convert into a type [`rustls`] can consume.
	///
	/// # Panics
	/// Panics if [`Certificate`] couldn't be parsed or contained no valid
	/// domain names. This can't happen if [`Certificate`] is constructed
	/// correctly from [`from_der`](Self::from_der).
	pub(crate) fn into_rustls(self) -> rustls::Certificate {
		rustls::Certificate(self.into())
	}
}

#[test]
fn validate() -> anyhow::Result<()> {
	use crate::KeyPair;

	let key_pair = KeyPair::new_self_signed("test");
	let certificate = key_pair.end_entity_certificate();
	assert_eq!(certificate, &Certificate::from_der(certificate.as_ref())?);

	Ok(())
}
