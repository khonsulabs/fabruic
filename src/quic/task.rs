//! Wrapper to handle closing async tasks in a concurrent way.

use std::{
	future::Future,
	panic,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use futures_channel::oneshot::{self, Receiver, Sender};
use futures_util::FutureExt;
use parking_lot::Mutex;
use tokio::task::{JoinError, JoinHandle};

use crate::error;

/// Wrapper to abort tasks when they are dropped.
#[derive(Debug)]
pub(super) struct Task<R, S = ()>(Arc<Mutex<Option<Inner<R, S>>>>);

impl<R, S> Clone for Task<R, S> {
	fn clone(&self) -> Self {
		Self(Arc::clone(&self.0))
	}
}

/// Inner wrapper for [`Task`].
#[derive(Debug)]
struct Inner<R, S> {
	/// Async task handle.
	handle: JoinHandle<R>,
	/// Channel for close signal.
	close: Sender<S>,
}

impl<R> Task<R> {
	/// Builds a new [`Task`].
	pub(super) fn new<T, F, S>(task: T) -> Task<R, S>
	where
		T: FnOnce(Receiver<S>) -> F,
		F: Future<Output = R> + Send + 'static,
		F::Output: Send + 'static,
	{
		let (sender, receiver) = oneshot::channel();

		// TODO: configurable executor
		let handle = tokio::spawn(task(receiver));

		Task(Arc::new(Mutex::new(Some(Inner {
			handle,
			close: sender,
		}))))
	}

	/// Builds a new empty [`Task`] that is already closed. This is useful to
	/// not have to wrap [`Task`] in another [`Option`].
	pub(super) fn empty() -> Self {
		Self(Arc::new(Mutex::new(None)))
	}
}

impl<R, S> Task<R, S> {
	/// Shuts down the [`Task`] by sending the close signal. Futher calls to
	/// [`close`](Self::close) or [`poll`](Future::poll)ing the [`Task`] will
	/// result in [`error::AlreadyClosed`].
	///
	/// # Notes
	/// The user is responsible to handle close messages through the
	/// [`Receiver`](futures_channel::oneshot::Receiver).
	///
	/// # Panics
	/// Will propagate any panics that happened in the task.
	pub(super) async fn close(&self, message: S) -> Result<R, error::AlreadyClosed> {
		if let Some(Inner { handle, close }) = self.0.lock().take() {
			// task could have finished and dropped the receiver, it's also possible that
			// the receiver got dropped otherwise, in any case, not our problem
			let _result = close.send(message);

			match handle.await.map_err(JoinError::into_panic) {
				Ok(result) => Ok(result),
				// propagate any panics
				Err(panic) => panic::resume_unwind(panic),
			}
		} else {
			Err(error::AlreadyClosed)
		}
	}
}

impl<R, S> Future for &Task<R, S> {
	type Output = Result<R, error::AlreadyClosed>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		// save the lock in a separate variable to be able to drop it
		let mut inner = self.0.lock();

		if let Some(Inner { handle, .. }) = inner.as_mut() {
			if let Poll::Ready(result) = handle.poll_unpin(cx) {
				// drop inner, `close` might be called simultaneously, so we don't handle this
				let _inner = inner.take();
				// drop `Mutex` before doing anything rash (parking_lot `Mutex` can't be
				// poisoned anyway)
				drop(inner);

				match result.map_err(JoinError::into_panic) {
					Ok(result) => Poll::Ready(Ok(result)),
					// propagate any panics
					Err(panic) => panic::resume_unwind(panic),
				}
			} else {
				Poll::Pending
			}
		} else {
			Poll::Ready(Err(error::AlreadyClosed))
		}
	}
}

#[cfg(test)]
mod test {
	use anyhow::{Error, Result};
	use futures_util::StreamExt;

	use super::Task;
	use crate::error;

	#[tokio::test]
	async fn empty() -> Result<()> {
		let task: Task<()> = Task::empty();
		assert!(matches!((&task).await, Err(error::AlreadyClosed)));

		Ok(())
	}

	#[tokio::test]
	async fn clone() -> Result<()> {
		let task_1: Task<bool> = Task::new(|_| async move { true });
		let task_2 = task_1.clone();

		assert!(matches!((&task_1).await, Ok(true)));
		assert!(matches!((&task_2).await, Err(error::AlreadyClosed)));

		Ok(())
	}

	#[tokio::test]
	async fn task() -> Result<()> {
		let (sender, receiver) = flume::unbounded();
		let (tester_sender, tester_receiver) = flume::unbounded();

		let task = Task::new(|mut shutdown| async move {
			let mut receiver = receiver.into_stream();

			while let Some(message) = futures_util::select_biased!(
				message = receiver.next() => message,
				_ = &mut shutdown => None,
			) {
				// send back our messages
				tester_sender.send(message)?;
			}

			// return `true`
			Result::<_, Error>::Ok(true)
		});

		// send a 100 messages
		for item in 0_usize..100 {
			sender.send(item)?;
		}

		// validate our returned value
		assert!(task.close(()).await??);
		// validate that `close` has properly closed
		assert!(matches!((&task).await, Err(error::AlreadyClosed)));

		// validate that we correctly sent all messages before shutting down
		let mut tester_receiver = tester_receiver.into_stream();
		let mut validate = 0;

		while let Some(item) = tester_receiver.next().await {
			assert_eq!(validate, item);
			validate += 1;
		}

		Ok(())
	}

	#[tokio::test]
	#[should_panic = "test"]
	// TODO: fix lint (https://github.com/rust-lang/rust-clippy/issues/7438)
	#[allow(clippy::semicolon_if_nothing_returned)]
	async fn panic_await() {
		let task: Task<()> = Task::new(|_| async move {
			panic!("test");
		});

		(&task).await.expect("should panic before unwrapping");
	}

	#[tokio::test]
	#[should_panic = "test"]
	// TODO: fix lint (https://github.com/rust-lang/rust-clippy/issues/7438)
	#[allow(clippy::semicolon_if_nothing_returned)]
	async fn panic_close() {
		let task = Task::new(|_| async move {
			panic!("test");
		});

		task.close(())
			.await
			.expect("should panic before unwrapping");
	}
}
