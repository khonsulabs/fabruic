//! [`Certificate`].

use std::time::Duration;

use serde::{Deserialize, Serialize};
use webpki::EndEntityCert;
use x509_parser::{certificate::X509Certificate, extensions::GeneralName};

use crate::{error::ParseCertificate, Error, Result};

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

impl Certificate {
	/// Build [`Certificate`] from DER-format. This is not meant as a full
	/// validation of a [`Certificate`], it just offers some sane protections.
	///
	/// # Errors
	/// - [`Error::ParseCertificate`] if the certificate couldn't be parsed
	///
	/// - [`Error::DanglingCertificate`] if the certificate contained
	///   uncorrelated bytes
	/// - [`Error::ExpiredCertificate`] if the certificate has expires
	/// - [`Error::DomainCertificate`] if the certificate doesn't contain a
	///   domain name
	pub fn from_der(certificate: Vec<u8>) -> Result<Self> {
		// parse certificate with `webpki`, which is what `rustls` uses, which is what
		// `quinn` uses
		let _ = match EndEntityCert::from(&certificate) {
			Ok(parsed) => parsed,
			Err(error) =>
				return Err(Error::ParseCertificate {
					certificate,
					error: ParseCertificate::WebPki(error),
				}),
		};

		// parse certificate with the `x509-parser, which is what `rcgen` uses
		let (trailing, parsed) = match X509Certificate::from_der(&certificate) {
			Ok((trailing, bytes)) => (trailing, bytes),
			Err(error) =>
				return Err(Error::ParseCertificate {
					certificate,
					error: ParseCertificate::X509(error),
				}),
		};

		// don't allow trailing bytes
		if !trailing.is_empty() {
			return Err(Error::DanglingCertificate {
				dangling: trailing.to_owned(),
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
			return Err(Error::ExpiredCertificate(certificate));
		}

		// certificate has to include domain names
		if parsed
			.tbs_certificate
			.subject_alternative_name()
			.filter(|name| !name.1.general_names.is_empty())
			.is_none()
		{
			return Err(Error::DomainCertificate(certificate));
		}

		// TODO: extend validation to use something like
		// `webpki::EndEntityCert::verify_is_valid_tls_client_cert`

		Ok(Self(certificate))
	}

	/// Build [`Certificate`] from DER-format. This skips the validation from
	/// [`from_der`](Self::from_der), which isn't `unsafe`, but will fail
	/// nonetheless when used on an [`Endpoint`](crate::Endpoint).
	#[must_use]
	pub fn unchecked_from_der(certificate: Vec<u8>) -> Self {
		Self(certificate)
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
			.map(|name| {
				name.1
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

	/// Convert into a type [`rustls`] can consume.
	///
	/// # Panics
	/// Panics if [`Certificate`] couldn't be parsed or contained no valid
	/// domain names. This can't happen if [`Certificate`] is constructed
	/// correctly from [`from_der`](Self::from_der).
	pub(crate) fn into_rustls(self) -> rustls::Certificate {
		rustls::Certificate(self.into())
	}

	/// Convert into a type [`quinn`] can consume.
	///
	/// # Panics
	/// Panics if [`Certificate`] couldn't be parsed or contained no valid
	/// domain names. This can't happen if [`Certificate`] is constructed
	/// correctly from [`from_der`](Self::from_der).
	pub(crate) fn as_quinn(&self) -> quinn::Certificate {
		quinn::Certificate::from_der(self.as_ref()).expect("`Certificate` couldn't be parsed")
	}
}

#[test]
fn validate() -> anyhow::Result<()> {
	use crate::KeyPair;

	let (certificate, _) = KeyPair::new_self_signed("test").into_parts();

	assert_eq!(
		certificate,
		Certificate::from_der(certificate.clone().into())?
	);

	Ok(())
}
