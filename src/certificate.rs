//! Creating [`Certificate`]s.

use std::{
	fmt::{self, Debug, Formatter},
	time::Duration,
};

use rustls::sign;
use serde::{Deserialize, Serialize, Serializer};
use webpki::EndEntityCert;
use x509_parser::{certificate::X509Certificate, extensions::GeneralName};
use zeroize::Zeroize;

use crate::{error::ParseCertificate, Error, Result};

/// A public Certificate. You can distribute it freely to peers.
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
	/// correctly from [`from_der`](Certificate::from_der).
	#[allow(clippy::expect_used)]
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
}

/// A private Key.
///
/// # Safety
/// Never give this to anybody.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey(Option<Vec<u8>>);

impl Debug for PrivateKey {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.write_str("[[redacted]]")
	}
}

impl PrivateKey {
	/// Build [`PrivateKey`] from DER-format. This is not meant as a full
	/// validation of a [`PrivateKey`], it just offers some sane protections.
	///
	/// # Errors
	/// [`Error::ParsePrivateKey`] if the certificate couldn't be parsed.
	pub fn from_der(private_key: Vec<u8>) -> Result<Self> {
		let private_key = rustls::PrivateKey(private_key);

		#[allow(box_pointers)]
		let _key = sign::any_supported_type(&private_key).map_err(|_error| Error::ParsePrivateKey)?;

		Ok(Self(Some(private_key.0)))
	}

	/// Build [`PrivateKey`] from DER-format. This skips the validation from
	/// [`from_der`](Self::from_der), which isn't `unsafe`, but will fail
	/// nonetheless when used on an [`Endpoint`](crate::Endpoint).
	#[must_use]
	pub fn unchecked_from_der(private_key: Vec<u8>) -> Self {
		Self(Some(private_key))
	}
}

/// Gives read access to the [`PrivateKey`].
///
/// # Security
/// This is only dangerous in the sense that you aren't supposed to leak the
/// [`PrivateKey`]. Make sure to use this carefully!
pub trait Dangerous {
	/// Returns a [`&[u8]`](slice) to the [`PrivateKey`].
	///
	/// # Security
	/// This is only dangerous in the sense that you aren't supposed to leak the
	/// [`PrivateKey`]. Make sure to use this carefully!
	#[must_use]
	fn as_ref(private_key: &Self) -> &[u8];

	/// Returns a [`Vec<u8>`] to the [`PrivateKey`].
	///
	/// # Security
	/// This is only dangerous in the sense that you aren't supposed to leak the
	/// [`PrivateKey`]. Make sure to use this carefully!
	#[must_use]
	fn into(private_key: Self) -> Vec<u8>;

	/// Serialize with [`serde`].
	///
	/// # Security
	/// This is only dangerous in the sense that you aren't supposed to leak the
	/// [`PrivateKey`]. Make sure to use this carefully!
	///
	/// # Errors
	/// [`S::Error`](Serializer::Error) if serialization failed.
	fn serialize<S: Serializer>(private_key: &Self, serializer: S) -> Result<S::Ok, S::Error>;
}

impl Dangerous for PrivateKey {
	fn as_ref(private_key: &Self) -> &[u8] {
		#[allow(clippy::expect_used)]
		private_key.0.as_deref().expect("value already dropped")
	}

	fn into(mut private_key: Self) -> Vec<u8> {
		#[allow(clippy::expect_used)]
		private_key.0.take().expect("value already dropped")
	}

	fn serialize<S: Serializer>(private_key: &Self, serializer: S) -> Result<S::Ok, S::Error> {
		Serializer::serialize_newtype_struct(serializer, "PrivateKey", &private_key.0)
	}
}

/// Generate a self signed certificate.
pub fn generate_self_signed<S: Into<String>>(domain: S) -> (Certificate, PrivateKey) {
	#[allow(clippy::expect_used)]
	let key_pair = rcgen::generate_simple_self_signed([domain.into()])
		.expect("`rcgen` failed generating a self-signed certificate");

	(
		#[allow(clippy::expect_used)]
		Certificate::unchecked_from_der(
			key_pair
				.serialize_der()
				.expect("`rcgen` failed serializing a certificate"),
		),
		PrivateKey::unchecked_from_der(key_pair.serialize_private_key_der()),
	)
}

#[test]
fn validate() -> anyhow::Result<()> {
	let (certificate, private_key) = generate_self_signed("test");

	assert_eq!(
		certificate,
		Certificate::from_der(certificate.clone().into())?
	);

	assert_eq!(
		private_key,
		PrivateKey::from_der(Dangerous::into(private_key.clone()))?,
	);

	Ok(())
}

#[test]
#[allow(box_pointers)]
fn serialize() -> anyhow::Result<()> {
	use bincode::{config::DefaultOptions, Options, Serializer};

	let (_, private_key) = generate_self_signed("test");

	let mut buffer = Vec::new();

	Dangerous::serialize(
		&private_key,
		&mut Serializer::new(
			&mut buffer,
			DefaultOptions::default()
				.with_fixint_encoding()
				.allow_trailing_bytes(),
		),
	)?;

	assert_eq!(private_key, bincode::deserialize(&buffer)?);

	Ok(())
}

#[test]
fn debug() {
	let (_, private_key) = generate_self_signed("test");
	assert_eq!("[[redacted]]", format!("{:?}", private_key));
}
