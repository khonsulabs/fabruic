//! [`Incoming`] stream of a [`Connection`](crate::Connection).

use std::fmt::{self, Debug, Formatter};

use futures_util::StreamExt;
use quinn::{RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};

use super::ReceiverStream;
use crate::{error, Receiver, Sender};

/// An intermediate state to define which type to accept in this stream. See
/// [`accept_stream`](Self::accept).
#[must_use = "`Incoming` does nothing unless accepted with `Incoming::accept`"]
pub struct Incoming<T: DeserializeOwned> {
	/// [`SendStream`] to build [`Sender`].
	sender: SendStream,
	/// [`RecvStream`] to build [`Receiver`].
	receiver: ReceiverStream<T>,
	/// Requested type.
	r#type: Option<Result<T, error::Incoming>>,
}

impl<T: DeserializeOwned> Debug for Incoming<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Incoming")
			.field("sender", &self.sender)
			.field("receiver", &"ReceiverStream")
			.field("type", &"Option<Result<T>>")
			.finish()
	}
}

impl<T: DeserializeOwned> Incoming<T> {
	/// Builds a new [`Incoming`] from raw [`quinn`] types.
	pub(super) fn new(sender: SendStream, receiver: RecvStream) -> Self {
		Self {
			sender,
			receiver: ReceiverStream::new(receiver),
			r#type: None,
		}
	}

	/// Returns the type information for that stream.
	///
	/// # Errors
	/// - [`error::Incoming::Receiver`] if receiving the type information to the
	///   peer failed, see [`error::Receiver`] for more details
	/// - [`error::Incoming::Closed`] if the stream was closed
	// TODO: fix lint
	#[allow(unused_lifetimes)]
	// TODO: return different state, because error can't be cloned and state is
	// unusable anyway
	#[allow(clippy::missing_panics_doc)]
	pub async fn r#type(&mut self) -> Result<&T, &error::Incoming> {
		if let Some(ref r#type) = self.r#type {
			r#type.as_ref()
		} else {
			let r#type = self
				.receiver
				.next()
				.await
				.map_or(Err(error::Incoming::Closed), |result| {
					result.map_err(error::Incoming::Receiver)
				});
			// TODO: replace with `Option::insert`
			self.r#type = Some(r#type);
			self.r#type
				.as_ref()
				.expect("`type` just inserted missing")
				.as_ref()
		}
	}

	/// Accept the incoming stream with the given types.
	///
	/// Use `S` and `R` to define which type this stream is sending and
	/// receiving.
	///
	/// # Errors
	/// - [`error::Incoming::Receiver`] if receiving the type information to the
	///   peer failed, see [`error::Receiver`] for more details
	/// - [`error::Incoming::Closed`] if the stream was closed
	pub async fn accept<
		S: DeserializeOwned + Serialize + Send + 'static,
		R: DeserializeOwned + Serialize + Send + 'static,
	>(
		mut self,
	) -> Result<(Sender<S>, Receiver<R>), error::Incoming> {
		match self.r#type {
			Some(Ok(_)) => (),
			Some(Err(error)) => return Err(error),
			None => {
				let _type = self
					.receiver
					.next()
					.await
					.map_or(Err(error::Incoming::Closed), |result| {
						result.map_err(error::Incoming::Receiver)
					});
			}
		}

		let sender = Sender::new(self.sender);
		let receiver = Receiver::new(self.receiver.transmute());

		Ok((sender, receiver))
	}
}
