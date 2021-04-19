//! X509 public key certificate handling.

mod certificate;
mod certificate_chain;
pub mod private_key;
use std::{convert::TryFrom, sync::Arc};

pub use certificate::Certificate;
pub use certificate_chain::CertificateChain;
pub use private_key::PrivateKey;
use rustls::sign::CertifiedKey;
use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serializer};

use crate::error;

/// A key-pair, consisting of a [`CertificateChain`] and [`PrivateKey`].
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyPair {
	/// The public [`CertificateChain`].
	certificate_chain: CertificateChain,
	/// The secret [`PrivateKey`].
	#[serde(deserialize_with = "deserialize_private_key")]
	private_key: PrivateKey,
}

impl TryFrom<(CertificateChain, PrivateKey)> for KeyPair {
	type Error = error::KeyPair;

	fn try_from(
		(certificate_chain, private_key): (CertificateChain, PrivateKey),
	) -> Result<Self, Self::Error> {
		Self::from_parts(certificate_chain, private_key)
	}
}

impl KeyPair {
	/// Generate a self signed certificate.
	pub fn new_self_signed<S: Into<String>>(domain: S) -> Self {
		let key_pair = rcgen::generate_simple_self_signed([domain.into()])
			.expect("`rcgen` failed generating a self-signed certificate");

		let certificate = Certificate::unchecked_from_der(
			key_pair
				.serialize_der()
				.expect("`rcgen` failed serializing a certificate"),
		);
		let certificate_chain = CertificateChain::unchecked_from_certificates([certificate]);

		let private_key = PrivateKey::unchecked_from_der(key_pair.serialize_private_key_der());

		Self {
			certificate_chain,
			private_key,
		}
	}

	/// Builds a new [`KeyPair`] from the given [`CertificateChain`] and
	/// [`PrivateKey`]. Will validate if they pair up correctly.
	///
	/// This presumes that [`CertificateChain`] and [`PrivateKey`] are valid,
	/// see [`CertificateChain::from_certificates`] and
	/// [`PrivateKey::from_der`].
	///
	/// # Errors
	/// TODO: this doesn't do any validation yet
	pub fn from_parts(
		certificate_chain: CertificateChain,
		private_key: PrivateKey,
	) -> Result<Self, error::KeyPair> {
		// TODO: validate if they pair up, see <https://github.com/ctz/rustls/issues/618>
		Ok(Self {
			certificate_chain,
			private_key,
		})
	}

	/// Build [`KeyPair`] from the given [`CertificateChain`] and
	/// [`PrivateKey`]. This skips the validation from
	/// [`from_parts`](Self::from_parts), which isn't `unsafe`, but could fail
	/// nonetheless when used on an [`Endpoint`](crate::Endpoint).
	#[must_use]
	pub fn unchecked_from_parts(
		certificate_chain: CertificateChain,
		private_key: PrivateKey,
	) -> Self {
		Self {
			certificate_chain,
			private_key,
		}
	}

	/// Return the [`CertificateChain`] of this [`KeyPair`].
	#[must_use]
	pub const fn certificate_chain(&self) -> &CertificateChain {
		&self.certificate_chain
	}

	/// Returns the end-entity [`Certificate`].
	///
	/// # Panics
	/// If the [`KeyPair`] is invalid. This can't happen if validated
	/// through [`from_parts`](Self::from_parts).
	#[must_use]
	pub fn end_entity_certificate(&self) -> &Certificate {
		self.certificate_chain.end_entity_certificate()
	}

	/// Return the secret [`PrivateKey`] of this [`KeyPair`].
	#[must_use]
	pub const fn private_key(&self) -> &PrivateKey {
		&self.private_key
	}

	/// Destructure [`KeyPair`] into it's owned parts.
	#[must_use]
	#[allow(clippy::missing_const_for_fn)]
	pub fn into_parts(self) -> (CertificateChain, PrivateKey) {
		(self.certificate_chain, self.private_key)
	}

	/// Destructure [`KeyPair`] into it's borrowed parts.
	#[must_use]
	pub const fn parts(&self) -> (&CertificateChain, &PrivateKey) {
		(&self.certificate_chain, &self.private_key)
	}

	/// Convert into a type [`rustls`] can consume.
	pub(crate) fn into_rustls(self) -> CertifiedKey {
		CertifiedKey::new(
			self.certificate_chain.into_rustls(),
			#[allow(box_pointers)]
			Arc::new(self.private_key.into_rustls()),
		)
	}
}

/// Gives serialization access to [`KeyPair`].
///
/// # Security
/// This is only dangerous in the sense that you aren't supposed to leak the
/// [`PrivateKey`]. Make sure to use this carefully!
pub trait Dangerous {
	/// Serialize with [`serde`].
	///
	/// # Security
	/// This is only dangerous in the sense that you aren't supposed to leak the
	/// [`PrivateKey`]. Make sure to use this carefully!
	///
	/// # Errors
	/// [`S::Error`](Serializer::Error) if serialization failed.
	fn serialize<S: Serializer>(key_pair: &Self, serializer: S) -> Result<S::Ok, S::Error>;
}

impl Dangerous for KeyPair {
	fn serialize<S: Serializer>(key_pair: &Self, serializer: S) -> Result<S::Ok, S::Error> {
		let mut serializer = serializer.serialize_struct("KeyPair", 2)?;
		serializer.serialize_field("certificate_chain", &key_pair.certificate_chain)?;
		// we can't directly serialize `PrivateKey`, so instead we serialize it's
		// innards - when deserializing we have to do this in revert and be careful not
		// to directly deserialize `PrivateKey`
		serializer.serialize_field(
			"private_key",
			private_key::Dangerous::as_ref(&key_pair.private_key),
		)?;
		serializer.end()
	}
}

/// Custom [`Deserializer`] for [`PrivateKey`] in [`KeyPair`].
///
/// We [`Serialize`](serde::Serialize) [`PrivateKey`] in [`KeyPair`] not
/// directly, we have to correspondingly do the same when [`Deserialize`]ing.
#[allow(single_use_lifetimes)]
fn deserialize_private_key<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
where
	D: Deserializer<'de>,
{
	Ok(PrivateKey::unchecked_from_der(Vec::<u8>::deserialize(
		deserializer,
	)?))
}

#[test]
fn serialize() -> anyhow::Result<()> {
	use bincode::{config::DefaultOptions, Options, Serializer};

	let key_pair = KeyPair::new_self_signed("test");

	let mut buffer = Vec::new();

	Dangerous::serialize(
		&key_pair,
		&mut Serializer::new(
			&mut buffer,
			DefaultOptions::default()
				.with_fixint_encoding()
				.allow_trailing_bytes(),
		),
	)?;

	assert_eq!(key_pair, bincode::deserialize(&buffer)?);

	Ok(())
}

#[test]
fn debug() {
	let key_pair = KeyPair::new_self_signed("test");
	assert_eq!(
		format!(
			"KeyPair {{ certificate_chain: {:?}, private_key: PrivateKey(\"[[redacted]]\") }}",
			key_pair.certificate_chain()
		),
		format!("{:?}", key_pair)
	);
}
