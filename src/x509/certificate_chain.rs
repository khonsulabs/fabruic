//! [`CertificateChain`].

use std::{convert::TryFrom, ops::Index, slice::Iter, vec::IntoIter};

use serde::{Deserialize, Serialize};

use crate::{error, Certificate};

/// A public [`Certificate`] chain, used to prese
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CertificateChain(Vec<Certificate>);

impl TryFrom<Vec<Certificate>> for CertificateChain {
	type Error = error::CertificateChain;

	fn try_from(certificates: Vec<Certificate>) -> Result<Self, Self::Error> {
		Self::from_certificates(certificates)
	}
}

impl IntoIterator for CertificateChain {
	type IntoIter = IntoIter<Self::Item>;
	type Item = Certificate;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl Index<usize> for CertificateChain {
	type Output = Certificate;

	fn index(&self, index: usize) -> &Self::Output {
		self.0.index(index)
	}
}

impl CertificateChain {
	/// Builds a new [`CertificateChain`] from the given [`Certificate`]s and
	/// validates it.
	///
	/// This presumes that [`Certificate`]s are valid, see
	/// [`Certificate::from_der`].
	///
	/// # Errors
	/// TODO: this doesn't do any validation yet
	pub fn from_certificates<C: Into<Vec<Certificate>>>(
		certificates: C,
	) -> Result<Self, error::CertificateChain> {
		Ok(Self(certificates.into()))
	}

	/// Builds [`CertificateChain`] from the given [`Certificate`]s. This skips
	/// the validation from [`from_certificates`](Self::from_certificates),
	/// which isn't `unsafe`, but could fail nonetheless when used on an
	/// [`Endpoint`](crate::Endpoint).
	pub fn unchecked_from_certificates<C: Into<Vec<Certificate>>>(certificates: C) -> Self {
		Self(certificates.into())
	}

	/// Returns the end-entity [`Certificate`].
	///
	/// # Panics
	/// If the [`CertificateChain`] is invalid. This can't happen if validated
	/// through [`from_certificates`](Self::from_certificates).
	#[must_use]
	pub fn into_end_entity_certificate(self) -> Certificate {
		self.0
			.into_iter()
			.next()
			.expect("`CertificateChain` is invalid")
	}

	/// Returns a reference to the end-entity [`Certificate`].
	///
	/// # Panics
	/// If the [`CertificateChain`] is invalid. This can't happen if validated
	/// through [`from_certificates`](Self::from_certificates).
	#[must_use]
	pub fn end_entity_certificate(&self) -> &Certificate {
		self.0.get(0).expect("`CertificateChain` is invalid")
	}

	/// Returns an iterator over the [`CertificateChain`].
	#[must_use]
	pub fn iter(&self) -> Iter<'_, Certificate> {
		self.0.iter()
	}

	/// Provides a reference to the [`Certificate`] at the given index.
	#[must_use]
	pub fn get(&self, index: usize) -> Option<&Certificate> {
		self.0.get(index)
	}

	/// Convert from a [`quinn`] type.
	pub(crate) fn from_quinn(certificate_chain: quinn::CertificateChain) -> Self {
		Self(
			certificate_chain
				.into_iter()
				.map(Certificate::from_rustls)
				.collect(),
		)
	}

	/// Convert into a type [`quinn`] can consume.
	pub(crate) fn as_quinn(&self) -> quinn::CertificateChain {
		quinn::CertificateChain::from_certs(self.0.iter().map(Certificate::as_quinn))
	}

	/// Convert into a type [`rustls`] can consume.
	pub(crate) fn into_rustls(self) -> Vec<rustls::Certificate> {
		self.0.into_iter().map(Certificate::into_rustls).collect()
	}
}
