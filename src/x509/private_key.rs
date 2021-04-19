//! [`PrivateKey`].

use std::{
	convert::TryFrom,
	fmt::{self, Debug, Formatter},
};

use rustls::sign::{self, SigningKey};
use serde::{Deserialize, Serializer};
use zeroize::Zeroize;

use crate::error;

/// A private key.
///
/// # Safety
/// Never give this to anybody.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey(Option<Vec<u8>>);

impl Debug for PrivateKey {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PrivateKey").field(&"[[redacted]]").finish()
	}
}

impl TryFrom<Vec<u8>> for PrivateKey {
	type Error = error::PrivateKey;

	fn try_from(certificate: Vec<u8>) -> Result<Self, Self::Error> {
		Self::from_der(certificate)
	}
}

impl PrivateKey {
	/// Build [`PrivateKey`] from DER-format. This is not meant as a full
	/// validation of a [`PrivateKey`], it just offers some sane protections.
	///
	/// # Errors
	/// [`error::PrivateKey`] if the certificate couldn't be parsed.
	pub fn from_der(private_key: Vec<u8>) -> Result<Self, error::PrivateKey> {
		let private_key = rustls::PrivateKey(private_key);

		#[allow(box_pointers)]
		if let Err(_error) = sign::any_supported_type(&private_key) {
			Err(error::PrivateKey(private_key.0))
		} else {
			Ok(Self(Some(private_key.0)))
		}
	}

	/// Build [`PrivateKey`] from DER-format. This skips the validation from
	/// [`from_der`](Self::from_der), which isn't `unsafe`, but will fail
	/// nonetheless when used on an [`Endpoint`](crate::Endpoint).
	#[must_use]
	pub fn unchecked_from_der(private_key: Vec<u8>) -> Self {
		Self(Some(private_key))
	}

	/// Convert into a type [`rustls`] can consume.
	///
	/// # Panics
	/// Panics if [`PrivateKey`] couldn't be parsed. This can't happen if
	/// [`PrivateKey`] is constructed correctly from
	/// [`from_der`](Self::from_der).
	#[allow(box_pointers)]
	pub(crate) fn into_rustls(self) -> Box<dyn SigningKey> {
		sign::any_supported_type(&rustls::PrivateKey(Dangerous::into(self)))
			.expect("`PrivateKey` not compatible with `rustls`")
	}

	/// Convert into a type [`quinn`] can consume.
	///
	/// # Panics
	/// Panics if [`PrivateKey`] couldn't be parsed. This can't happen if
	/// [`PrivateKey`] is constructed correctly from
	/// [`from_der`](Self::from_der).
	pub(crate) fn as_quinn(&self) -> quinn::PrivateKey {
		quinn::PrivateKey::from_der(Dangerous::as_ref(self))
			.expect("`PrivateKey` couldn't be parsed")
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
		private_key.0.as_deref().expect("value already dropped")
	}

	fn into(mut private_key: Self) -> Vec<u8> {
		private_key.0.take().expect("value already dropped")
	}

	fn serialize<S: Serializer>(private_key: &Self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_newtype_struct("PrivateKey", &private_key.0)
	}
}

#[cfg(test)]
mod test {
	use anyhow::Result;
	use bincode::{config::DefaultOptions, Options, Serializer};

	use super::*;
	use crate::KeyPair;

	#[test]
	fn validate() -> Result<()> {
		let (_, private_key) = KeyPair::new_self_signed("test").into_parts();

		assert_eq!(
			private_key,
			PrivateKey::from_der(Dangerous::into(private_key.clone()))?,
		);

		Ok(())
	}

	#[test]
	fn serialize() -> Result<()> {
		let (_, private_key) = KeyPair::new_self_signed("test").into_parts();

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
		let (_, private_key) = KeyPair::new_self_signed("test").into_parts();
		assert_eq!("PrivateKey(\"[[redacted]]\")", format!("{:?}", private_key));
	}
}
