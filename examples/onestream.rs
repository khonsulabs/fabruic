//! TODO

#![allow(clippy::missing_docs_in_private_items)]

use anyhow::{Error, Result};
use fabruic::{Endpoint, KeyPair};
use futures_util::StreamExt;

const SERVER_NAME: &str = "test";
const SERVER_PORT: u16 = 5001;
const CLIENTS: usize = 100;

#[tokio::main]
#[cfg_attr(test, test)]
async fn main() -> Result<()> {
	// generate a certificate pair
	let key_pair = KeyPair::new_self_signed(SERVER_NAME);

	// start the server
	let server = Endpoint::new_server(SERVER_PORT, key_pair.clone())?;
	let address = format!("quic://{}", server.local_address()?);
	println!("[server] Listening on {address}");
	tokio::spawn(run_server(server));

	// build a client
	let client = Endpoint::new_client()?;

	let connection = client
		.connect_pinned(address, key_pair.end_entity_certificate(), None)
		.await?
		.accept::<()>()
		.await?;
	connection.close_incoming().await?;

	// initiate a stream
	let (sender, receiver) = connection.open_stream::<String, String>(&()).await?;

	let tasks = (0..CLIENTS)
		.map(|_| {
			let sender = sender.clone();
			let mut receiver = receiver.clone();
			async move {
				sender.send(&String::from("test"))?;
				let value = receiver.next().await.expect("didn't get a response")?;
				assert_eq!(value, "test");
				Ok(())
			}
		})
		.collect::<Vec<_>>();

	futures_util::future::join_all(tasks)
		.await
		.into_iter()
		.collect::<Result<Vec<()>, Error>>()?;

	// wait for client to finish cleanly
	client.wait_idle().await;

	Ok(())
}

async fn run_server(mut server: Endpoint) -> Result<(), Error> {
	// start listening to new incoming connections
	// in this example we know there is `CLIENTS` number of clients, so we will not
	// wait for more
	let mut connection = server
		.next()
		.await
		.expect("connection failed")
		.accept::<()>()
		.await?;
	println!("[server] New Connection: {}", connection.remote_address());

	// start listening to new incoming streams
	// in this example we know there is only 1 incoming stream, so we will not wait
	// for more
	let incoming = connection.next().await.expect("no stream found")?;
	connection.close_incoming().await?;
	println!(
		"[server] New incoming stream from: {}",
		connection.remote_address()
	);

	// accept stream
	let (sender, mut receiver) = incoming.accept::<String, String>().await?;

	// start listening to new incoming messages
	// in this example we know there is only 1 incoming message, so we will not wait
	// for more
	while let Some(message) = receiver.next().await {
		let message = message?;
		sender.send(&message)?;
	}

	// wait for stream to finish
	sender.finish().await?;
	receiver.finish().await?;

	Ok(())
}
