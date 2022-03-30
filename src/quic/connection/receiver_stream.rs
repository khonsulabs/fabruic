//! Implementation of [`ReceiverStream`], a wrapper providing framing and
//! deserialization around [`RecvStream`](quinn::RecvStream).

use std::{
	marker::PhantomData,
	mem::size_of,
	pin::Pin,
	task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures_util::{
	stream::{FusedStream, Stream},
	FutureExt,
};
use pin_project::pin_project;
use quinn::{Chunk, ReadError, RecvStream, VarInt};
use transmog::OwnedDeserializer;

use crate::error::{self, SerializationError};

/// Wrapper around [`RecvStream`] providing framing and deserialization.
#[pin_project]
pub(super) struct ReceiverStream<M, F>
where
	F: OwnedDeserializer<M>,
{
	/// Store length of the currently processing message.
	length: usize,
	/// Store incoming chunks.
	buffer: BytesMut,
	/// [`Quinn`](quinn)s receiver.
	stream: RecvStream,
	/// True if the stream is complete.
	complete: bool,
	/// The deserialization format.
	pub(super) format: F,
	/// Type to be [`Deserialize`](serde::Deserialize)d
	_type: PhantomData<M>,
}

impl<M, F> ReceiverStream<M, F>
where
	F: OwnedDeserializer<M>,
	F::Error: SerializationError + 'static,
{
	/// Builds a new [`ReceiverStream`].
	pub(super) fn new(stream: RecvStream, format: F) -> Self {
		Self {
			length: 0,
			// 1480 bytes is a default MTU size configured by quinn-proto
			buffer: BytesMut::with_capacity(1480),
			stream,
			complete: false,
			format,
			_type: PhantomData,
		}
	}

	/// Transmutes this [`ReceiverStream`] to a different message type.
	pub(super) fn transmute<T, NewFormat>(self, format: NewFormat) -> ReceiverStream<T, NewFormat>
	where
		NewFormat: OwnedDeserializer<T>,
	{
		ReceiverStream {
			length: self.length,
			buffer: self.buffer,
			stream: self.stream,
			complete: self.complete,
			format,
			_type: PhantomData,
		}
	}

	/// Calls [`RecvStream::stop`](RecvStream::stop).
	///
	/// # Errors
	/// [`error::AlreadyClosed`] if it was already closed.
	pub(super) fn stop(&mut self) -> Result<(), error::AlreadyClosed> {
		self.stream
			.stop(VarInt::from_u32(0))
			.map_err(|_error| error::AlreadyClosed)
	}

	/// [`Poll`](std::future::Future::poll)s [`RecvStream`] for the next
	/// [`Chunk`] and stores it in [`ReceiverStream`]. Returns [`None`] if the
	/// [`Stream`] is finished.
	///
	/// # Errors
	/// [`ReadError`] on failure to read from the [`RecvStream`].
	fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<()>, ReadError>> {
		self.stream
			.read_chunk(usize::MAX, true)
			.poll_unpin(cx)
			.map_ok(|option| {
				option.map(|Chunk { bytes, .. }| {
					// reserves enough space to put in incoming bytes
					self.buffer.reserve(bytes.len());
					self.buffer.put(bytes);
				})
			})
	}

	/// Check if we currently have enough data to build
	/// [`length`](Self::length) and returns it. Returns [`None`] if there isn't
	/// enough data to extract [`length`](Self::length) yet.
	fn length(&mut self) -> Option<usize> {
		if self.length == 0 {
			(self.buffer.len() >= size_of::<u64>()).then(|| {
				// aquire the length by reading the first 8 bytes (u64)
				self.length = usize::try_from(self.buffer.get_uint_le(size_of::<u64>()))
					.expect("not a 64-bit system");

				self.length
			})
		} else {
			Some(self.length)
		}
	}

	/// [`Deserialize`](serde::Deserialize)s the currents
	/// [`buffer`](Self::buffer). Returns [`None`] if there isn't enough data to
	/// extract [`length()`](Self::length()) yet.
	///
	/// # Errors
	/// [`ErrorKind`] if `data` failed to be
	/// [`Deserialize`](serde::Deserialize)d.
	#[allow(clippy::as_conversions, trivial_casts)] // False positive
	fn deserialize(&mut self) -> Result<Option<M>, Box<dyn SerializationError>> {
		if let Some(length) = self.length() {
			if self.buffer.len() >= length {
				// split off the correct amount of data
				let data = self.buffer.split_to(length);
				// reset the length
				self.length = 0;

				// deserialize message
				self.format
					.deserialize_owned(&data)
					.map(Some)
					.map_err(|err| Box::new(err) as Box<dyn SerializationError>)
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	}
}

impl<M, F> Stream for ReceiverStream<M, F>
where
	F: OwnedDeserializer<M>,
	F::Error: SerializationError,
{
	type Item = Result<M, error::Receiver>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		use futures_util::ready;

		// did already have enough data to return a message without polling?
		if let Some(message) = self.deserialize().map_err(error::Receiver::Deserialize)? {
			// send back the message
			return Poll::Ready(Some(Ok(message)));
		}

		// try to poll for more data. This loop is important, because if the
		// stream receives data between returning Poll::Ready and our failed
		// attempt at deserializing a message beacuse we didn't have enough
		// data, we want to poll the stream again before yielding to the
		// runtime.
		loop {
			if ready!(self.poll(cx)?).is_some() {
				// The stream received some data, but we may not have a full packet.
				if let Some(message) = self.deserialize().map_err(error::Receiver::Deserialize)? {
					break Poll::Ready(Some(Ok(message)));
				}
			} else {
				// The stream has ended
				self.complete = true;
				break Poll::Ready(None);
			}
		}
	}
}

impl<M, F> FusedStream for ReceiverStream<M, F>
where
	F: OwnedDeserializer<M>,
	F::Error: SerializationError,
{
	fn is_terminated(&self) -> bool {
		self.complete
	}
}
