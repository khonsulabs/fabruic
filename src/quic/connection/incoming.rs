//! [`Incoming`] stream of a [`Connection`](crate::Connection).

use quinn::{RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};

use crate::{Receiver, Sender};

/// An intermediate state to define which type to accept in this stream. See
/// [`accept_stream`](Self::accept_stream).
#[must_use = "`Incoming` does nothing unless accepted with `Incoming::accept_stream`"]
#[derive(Debug)]
pub struct Incoming {
	/// [`SendStream`] to build [`Sender`].
	sender: SendStream,
	/// [`RecvStream`] to build [`Receiver`].
	receiver: RecvStream,
}

impl Incoming {
	/// Builds a new [`Incoming`] from raw [`quinn`] types.
	pub(super) fn new(sender: SendStream, receiver: RecvStream) -> Self {
		Self { sender, receiver }
	}

	/// Accept
	///
	/// Use `S` and `R` to define which type this stream is sending and
	/// receiving.
	#[must_use]
	pub fn accept_stream<T: DeserializeOwned + Serialize + Send>(self) -> (Sender<T>, Receiver<T>) {
		let sender = Sender::new(self.sender);
		let receiver = Receiver::new(self.receiver);

		(sender, receiver)
	}
}
