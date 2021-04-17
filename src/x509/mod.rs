//! X509 public key certificate handling.

mod certificate;
pub mod private_key;
use std::sync::Arc;

pub use certificate::Certificate;
pub use private_key::PrivateKey;
use rustls::sign::CertifiedKey;
use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serializer};

use crate::Result;

/// A key-pair, consisting of a [`Certificate`] and [`PrivateKey`].
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyPair {
	/// The public [`Certificate`].
	certificate: Certificate,
	/// The secret [`PrivateKey`].
	#[serde(deserialize_with = "deserialize_private_key")]
	private_key: PrivateKey,
}

impl KeyPair {
	/// Generate a self signed [`Certificate`].
	pub fn new_self_signed<S: Into<String>>(domain: S) -> Self {
		let key_pair = rcgen::generate_simple_self_signed([domain.into()])
			.expect("`rcgen` failed generating a self-signed certificate");

		let certificate = Certificate::unchecked_from_der(
			key_pair
				.serialize_der()
				.expect("`rcgen` failed serializing a certificate"),
		);

		let private_key = PrivateKey::unchecked_from_der(key_pair.serialize_private_key_der());

		Self {
			certificate,
			private_key,
		}
	}

	/// Builds a new [`KeyPair`] from the given [`Certificate`] and
	/// [`PrivateKey`].
	///
	/// Will validate if they pair up, for extended validation see
	/// [`Certificate::from_der`] and [`PrivateKey::from_der`].
	///
	/// # Errors
	/// TODO: this doesn't do any validation yet
	pub fn from_parts(certificate: Certificate, private_key: PrivateKey) -> Result<Self> {
		// TODO: validate if they pair up, see <https://github.com/ctz/rustls/issues/618>
		Ok(Self {
			certificate,
			private_key,
		})
	}

	/// Return the public [`Certificate`] of this [`KeyPair`].
	#[must_use]
	pub const fn certificate(&self) -> &Certificate {
		&self.certificate
	}

	/// Return the secret [`PrivateKey`] of this [`KeyPair`].
	#[must_use]
	pub const fn private_key(&self) -> &PrivateKey {
		&self.private_key
	}

	/// Destructure [`KeyPair`] into it's owned parts.
	#[must_use]
	#[allow(clippy::missing_const_for_fn)]
	pub fn into_parts(self) -> (Certificate, PrivateKey) {
		(self.certificate, self.private_key)
	}

	/// Destructure [`KeyPair`] into it's borrowed parts.
	#[must_use]
	pub const fn parts(&self) -> (&Certificate, &PrivateKey) {
		(&self.certificate, &self.private_key)
	}

	/// Convert into a type [`rustls`] can consume.
	pub(crate) fn into_rustls(self) -> CertifiedKey {
		CertifiedKey::new(
			vec![self.certificate.into_rustls()],
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
		serializer.serialize_field("certificate", &key_pair.certificate)?;
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
			"KeyPair {{ certificate: {:?}, private_key: PrivateKey(\"[[redacted]]\") }}",
			key_pair.certificate()
		),
		format!("{:?}", key_pair)
	);
}
