//! [`Receiver`] part of a stream.

use std::{
	convert::TryFrom,
	fmt::{self, Debug, Formatter},
	marker::PhantomData,
	mem::size_of,
	pin::Pin,
	task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures_channel::oneshot;
use futures_util::{stream::Stream, FutureExt, StreamExt};
use pin_project::pin_project;
use quinn::{crypto::rustls::TlsSession, Chunk, VarInt};
use serde::de::DeserializeOwned;

use super::Task;
use crate::{Error, Result};

/// Used to receive data from a stream.
///
///  # Errors
/// [`Error::Deserialize`] if `data` failed to be
/// [`Deserialize`](serde::Deserialize)d.
#[derive(Clone)]
pub struct Receiver<T: 'static> {
	/// Send [`Deserialize`](serde::Deserialize)d data to the sending task.
	receiver: flume::r#async::RecvStream<'static, T>,
	/// [`Task`] handle that does the receiving from the stream.
	task: Task<Result<()>>,
}

impl<T> Debug for Receiver<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Receiver")
			.field("receiver", &"RecvStream<T>")
			.field("task", &self.task)
			.finish()
	}
}

impl<T> Receiver<T> {
	/// Builds a new [`Receiver`] from a raw [`quinn`] type. Spawns a task that
	/// receives data from the stream.
	pub(super) fn new(mut stream: quinn::RecvStream) -> Self
	where
		T: DeserializeOwned + Send,
	{
		// receiver channels
		let (sender, receiver) = flume::unbounded();
		let receiver = receiver.into_stream();

		// `Task` handling `Receiver`
		let (shutdown_sender, shutdown_receiver) = oneshot::channel();
		let task = Task::new(
			async move {
				/// Help Group Messages
				enum Message<T> {
					/// Data arrived from stream.
					Data(T),
					/// [`Receiver`] asked to close.
					Close,
				}

				let mut reader = ReceiverStream::new(&mut stream);
				let mut shutdown = shutdown_receiver;

				while let Some(message) = allochronic_util::select! {
					message: &mut reader => message.transpose()?.map(Message::Data),
					shutdown: &mut shutdown => shutdown.ok().map(|_| Message::Close),
				} {
					match message {
						Message::Data(message) => {
							// the receiver might have been dropped
							if sender.send(message).is_err() {
								break;
							}
						}
						Message::Close => {
							stream
								.stop(VarInt::from_u32(0))
								.map_err(|_error| Error::AlreadyClosed)?;
							break;
						}
					}
				}

				Ok(())
			},
			shutdown_sender,
		);

		Self { receiver, task }
	}

	/// Wait for the [`Receiver`] part of the stream to finish gracefully.
	///
	/// This can only be achieved through the peer's
	/// [`Sender::finish`](crate::Sender::finish) or an error.
	///
	/// # Errors
	/// - [`Error::Read`] if the [`Receiver`] failed to read from the stream
	/// - [`Error::AlreadyClosed`] if it has already been closed
	pub async fn finish(&self) -> Result<()> {
		(&self.task).await?
	}

	/// Close the [`Receiver`] immediately. To close a [`Receiver`] gracefully
	/// use [`finish`](Self::finish).
	///
	/// # Errors
	/// - [`Error::Read`] if the [`Receiver`] failed to read from the stream
	/// - [`Error::AlreadyClosed`] if it has already been closed
	pub async fn close(&self) -> Result<()> {
		self.task.close(()).await?
	}
}

impl<T> Stream for Receiver<T> {
	type Item = T;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.receiver.poll_next_unpin(cx)
	}
}

/// Wrapper around [`RecvStream`](quinn::RecvStream) to implement framing.
#[pin_project]
struct ReceiverStream<'s, T: DeserializeOwned> {
	/// Store length of the currently processing message.
	length: usize,
	/// Store incoming chunks.
	buffer: BytesMut,
	/// [`Quinn`](quinn)s receiver.
	reader: quinn::generic::ReadChunk<'s, TlsSession>,
	/// Type to be [`Deserialize`](serde::Deserialize)d
	_type: PhantomData<T>,
}

impl<'s, T: DeserializeOwned> ReceiverStream<'s, T> {
	/// Builds a new [`ReceiverStream`].
	fn new(stream: &'s mut quinn::RecvStream) -> Self {
		Self {
			length: 0,
			// 1480 bytes is a default MTU size configured by quinn-proto
			buffer: BytesMut::with_capacity(1480),
			reader: stream.read_chunk(usize::MAX, true),
			_type: PhantomData,
		}
	}

	/// [`Poll`](std::future::Future::poll)s [`RecvStream`](quinn::RecvStream)
	/// for the next [`Chunk`] and stores it in [`ReceiverStream`]. Returns
	/// [`None`] if the [`Stream`] is finished.
	///
	/// # Errors
	/// [`Error::Read`] if the [`Receiver`] failed to read from the
	/// [`RecvStream`](quinn::RecvStream).
	fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<()>>> {
		self.reader
			.poll_unpin(cx)
			.map_ok(|option| {
				option.map(|Chunk { bytes, .. }| {
					// reserves enough space to put in incoming bytes
					self.buffer.reserve(bytes.len());
					self.buffer.put(bytes);
				})
			})
			.map_err(Error::Read)
	}

	/// Check if we currently have enough data to build
	/// [`length`](Self::length) and returns it. Returns [`None`] if there isn't
	/// enough data to extract [`length`](Self::length) yet.
	#[allow(clippy::unwrap_in_result)]
	fn length(&mut self) -> Option<usize> {
		if self.length == 0 {
			if self.buffer.len() >= size_of::<u64>() {
				#[allow(clippy::expect_used)]
				{
					// aquire the length by reading the first 8 bytes (u64)
					self.length = usize::try_from(self.buffer.get_uint_le(size_of::<u64>()))
						.expect("not a 64-bit system");
				}

				Some(self.length)
			} else {
				None
			}
		} else {
			Some(self.length)
		}
	}

	/// [`Deserialize`](serde::Deserialize)s the currents
	/// [`bufer`](Self::buffer) with the given `length`. Returns [`None`] if
	/// there isn't enough data to extract [`length`](Self::length) yet.
	///
	/// # Errors
	/// [`Error::Deserialize`] if `data` failed to be
	/// [`Deserialize`](serde::Deserialize)d.
	fn deserialize(&mut self, length: usize) -> Result<Option<T>> {
		if self.buffer.len() >= length {
			// split off the correct amount of data
			let data = self.buffer.split_to(length).reader();
			// reset the length
			self.length = 0;

			// deserialize message
			// TODO: configure bincode, for example make it bounded
			#[allow(box_pointers)]
			bincode::deserialize_from::<_, T>(data)
				.map(Some)
				.map_err(|error| Error::Deserialize(*error))
		} else {
			Ok(None)
		}
	}
}

impl<T: DeserializeOwned> Stream for ReceiverStream<'_, T> {
	type Item = Result<T>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		use futures_util::ready;

		// do we have enough data to extract the length?
		if let Some(length) = self.length() {
			// did we receive enough data to deserialize the message?
			if let Some(message) = self.deserialize(length)? {
				// send back the message
				Poll::Ready(Some(Ok(message)))
			}
			// try to poll for more data
			else if ready!(self.poll(cx)?).is_some() {
				// did we receive enough data to deserialize the message?
				self.deserialize(length)?
					.map_or(Poll::Pending, |message| Poll::Ready(Some(Ok(message))))
			}
			// stream has ended
			else {
				Poll::Ready(None)
			}
		}
		// try to poll for more data
		else if ready!(self.poll(cx)?).is_some() {
			// did we receive enough data to extract the length?
			if let Some(length) = self.length() {
				self.deserialize(length)?
					.map_or(Poll::Pending, |message| Poll::Ready(Some(Ok(message))))
			} else {
				Poll::Pending
			}
		}
		// stream has ended
		else {
			Poll::Ready(None)
		}
	}
}
