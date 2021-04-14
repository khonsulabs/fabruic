//! [`Incoming`] stream of a [`Connection`](crate::Connection).

use std::fmt::{self, Debug, Formatter};

use futures_util::StreamExt;
use quinn::{RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};

use super::ReceiverStream;
use crate::{Error, Receiver, Result, Sender};

/// An intermediate state to define which type to accept in this stream. See
/// [`accept_stream`](Self::accept).
#[must_use = "`Incoming` does nothing unless accepted with `Incoming::accept`"]
pub struct Incoming<T: DeserializeOwned> {
	/// [`SendStream`] to build [`Sender`].
	sender: SendStream,
	/// [`RecvStream`] to build [`Receiver`].
	receiver: ReceiverStream<T>,
	/// Requested type.
	r#type: Option<Result<T>>,
}

impl<T: DeserializeOwned> Debug for Incoming<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Incoming")
			.field("sender", &self.sender)
			.field("receiver", &"ReceiverStream<T>")
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
	/// [`Error::NoType`] if the stream was closed before type information could
	/// be received.
	// TODO: fix lint
	#[allow(unused_lifetimes)]
	pub async fn r#type(&mut self) -> Result<&T, &Error> {
		if let Some(ref r#type) = self.r#type {
			r#type.as_ref()
		} else {
			let r#type = self.receiver.next().await.unwrap_or(Err(Error::NoType));
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
	/// [`Error::NoType`] if the stream was closed before type information could
	/// be received.
	pub async fn accept<
		S: DeserializeOwned + Serialize + Send + 'static,
		R: DeserializeOwned + Serialize + Send + 'static,
	>(
		mut self,
	) -> Result<(Sender<S>, Receiver<R>)> {
		match self.r#type {
			Some(Ok(_)) => (),
			Some(Err(error)) => return Err(error),
			None => {
				let _type = self.receiver.next().await.unwrap_or(Err(Error::NoType))?;
			}
		}

		let sender = Sender::new(self.sender);
		let receiver = Receiver::new(self.receiver.transmute());

		Ok((sender, receiver))
	}
}
