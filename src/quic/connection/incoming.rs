//! [`Incoming`] stream of a [`Connection`](crate::Connection).

use std::fmt::{self, Debug, Formatter};

use futures_util::StreamExt;
use quinn::{RecvStream, SendStream};
use transmog::{Format, OwnedDeserializer};

use super::ReceiverStream;
use crate::{
	error::{self, SerializationError},
	Receiver, Sender,
};

/// An intermediate state to define which type to accept in this stream. See
/// [`accept_stream`](Self::accept).
#[must_use = "`Incoming` does nothing unless accepted with `Incoming::accept`"]
pub struct Incoming<T, F: OwnedDeserializer<T>> {
	/// [`SendStream`] to build [`Sender`].
	sender: SendStream,
	/// [`RecvStream`] to build [`Receiver`].
	receiver: ReceiverStream<T, F>,
	/// Requested type.
	r#type: Option<Result<T, error::Incoming>>,
}

impl<T, F> Debug for Incoming<T, F>
where
	F: OwnedDeserializer<T>,
{
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Incoming")
			.field("sender", &self.sender)
			.field("receiver", &"ReceiverStream")
			.field("type", &"Option<Result<T>>")
			.finish()
	}
}

impl<T, F> Incoming<T, F>
where
	F: OwnedDeserializer<T> + Clone,
	F::Error: SerializationError,
{
	/// Builds a new [`Incoming`] from raw [`quinn`] types.
	pub(super) fn new(sender: SendStream, receiver: RecvStream, format: F) -> Self {
		Self {
			sender,
			receiver: ReceiverStream::new(receiver, format),
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
	pub async fn accept<S: Send + 'static, R: Send + 'static>(
		self,
	) -> Result<(Sender<S, F>, Receiver<R>), error::Incoming>
	where
		F: OwnedDeserializer<R> + Format<'static, S> + 'static,
		<F as Format<'static, S>>::Error: SerializationError,
		<F as Format<'static, R>>::Error: SerializationError,
	{
		let format = self.receiver.format.clone();
		self.accept_with_format(format).await
	}

	/// Accept the incoming stream with the given types, using `format` for
	/// serializing the stream.
	///
	/// Use `S` and `R` to define which type this stream is sending and
	/// receiving.
	///
	/// # Errors
	/// - [`error::Incoming::Receiver`] if receiving the type information to the
	///   peer failed, see [`error::Receiver`] for more details
	/// - [`error::Incoming::Closed`] if the stream was closed
	pub async fn accept_with_format<S: Send + 'static, R: Send + 'static, NewFormat>(
		mut self,
		format: NewFormat,
	) -> Result<(Sender<S, NewFormat>, Receiver<R>), error::Incoming>
	where
		NewFormat: OwnedDeserializer<R> + Format<'static, S> + Clone + 'static,
		<NewFormat as Format<'static, S>>::Error: SerializationError,
		<NewFormat as Format<'static, R>>::Error: SerializationError,
	{
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

		let sender = Sender::new(self.sender, format.clone());
		let receiver = Receiver::new(self.receiver.transmute(format));

		Ok((sender, receiver))
	}
}
