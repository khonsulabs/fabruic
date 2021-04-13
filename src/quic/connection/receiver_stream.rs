//! Implementation of [`ReceiverStream`], a wrapper providing framing and
//! deserialization around [`RecvStream`](quinn::RecvStream).

use std::{
	convert::TryFrom,
	marker::PhantomData,
	mem::size_of,
	pin::Pin,
	task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures_util::{stream::Stream, FutureExt};
use pin_project::pin_project;
use quinn::{Chunk, RecvStream, VarInt};
use serde::de::DeserializeOwned;

use crate::{Error, Result};

/// Wrapper around [`RecvStream`] providing framing and deserialization.
#[pin_project]
pub(super) struct ReceiverStream<M: DeserializeOwned> {
	/// Store length of the currently processing message.
	length: usize,
	/// Store incoming chunks.
	buffer: BytesMut,
	/// [`Quinn`](quinn)s receiver.
	stream: RecvStream,
	/// Type to be [`Deserialize`](serde::Deserialize)d
	_type: PhantomData<M>,
}

impl<M: DeserializeOwned> ReceiverStream<M> {
	/// Builds a new [`ReceiverStream`].
	pub(super) fn new(stream: RecvStream) -> Self {
		Self {
			length: 0,
			// 1480 bytes is a default MTU size configured by quinn-proto
			buffer: BytesMut::with_capacity(1480),
			stream,
			_type: PhantomData,
		}
	}

	/// Transmutes this [`ReceiverStream`] to a different message type.
	pub(super) fn transmute<T: DeserializeOwned>(self) -> ReceiverStream<T> {
		ReceiverStream {
			length: self.length,
			buffer: self.buffer,
			stream: self.stream,
			_type: PhantomData,
		}
	}

	/// Calls [`RecvStream::stop`](quinn::generic::RecvStream::stop).
	///
	/// # Errors
	/// [`Error::AlreadyClosed`] if it was already closed.
	pub(super) fn stop(&mut self) -> Result<()> {
		self.stream
			.stop(VarInt::from_u32(0))
			.map_err(|_error| Error::AlreadyClosed)
	}

	/// [`Poll`](std::future::Future::poll)s [`RecvStream`] for the next
	/// [`Chunk`] and stores it in [`ReceiverStream`]. Returns [`None`] if the
	/// [`Stream`] is finished.
	///
	/// # Errors
	/// [`Error::Read`] on failure to read from the [`RecvStream`].
	fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<()>>> {
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
			.map_err(Error::Read)
	}

	/// Check if we currently have enough data to build
	/// [`length`](Self::length) and returns it. Returns [`None`] if there isn't
	/// enough data to extract [`length`](Self::length) yet.
	#[allow(clippy::unwrap_in_result)]
	fn length(&mut self) -> Option<usize> {
		if self.length == 0 {
			(self.buffer.len() >= size_of::<u64>()).then(|| {
				#[allow(clippy::expect_used)]
				{
					// aquire the length by reading the first 8 bytes (u64)
					self.length = usize::try_from(self.buffer.get_uint_le(size_of::<u64>()))
						.expect("not a 64-bit system");
				}

				self.length
			})
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
	fn deserialize(&mut self, length: usize) -> Result<Option<M>> {
		if self.buffer.len() >= length {
			// split off the correct amount of data
			let data = self.buffer.split_to(length).reader();
			// reset the length
			self.length = 0;

			// deserialize message
			// TODO: configure bincode, for example make it bounded
			#[allow(box_pointers)]
			bincode::deserialize_from::<_, M>(data)
				.map(Some)
				.map_err(|error| Error::Deserialize(*error))
		} else {
			Ok(None)
		}
	}
}

impl<M: DeserializeOwned> Stream for ReceiverStream<M> {
	type Item = Result<M>;

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
