use anyhow::{Error, Result};
use fabruic::Endpoint;
use futures_util::{future, StreamExt, TryFutureExt};

const SERVER_NAME: &str = "test";
const SERVER_PORT: u16 = 5000;
const CLIENTS: usize = 100;

#[tokio::main]
#[cfg_attr(test, test)]
async fn main() -> Result<()> {
	// collect all tasks
	let mut tasks = Vec::with_capacity(CLIENTS + 1);

	// generate a certificate pair
	let (certificate, private_key) = fabruic::generate_self_signed(SERVER_NAME);

	// build the server
	// we want to do this outside to reserve the `SERVER_PORT`, otherwise spawned
	// clients may take it
	let mut server = Endpoint::new_server(SERVER_PORT, certificate.clone(), private_key)?;
	let address = format!("quic://{}", server.local_address()?);

	// start the server
	tasks.push({
		tokio::spawn(async move {
			println!("[server] Listening on {}", server.local_address()?);

			// collect incoming connection tasks
			let mut connections = Vec::with_capacity(CLIENTS);

			// start listening to new incoming connections
			// in this example we know there is `CLIENTS` number of clients, so we will not
			// wait for more
			for _ in 0..CLIENTS {
				let mut connection = server
					.next()
					.await
					.expect("connection failed")
					.accept::<()>()
					.await?;
				println!("[server] New Connection: {}", connection.remote_address());

				// every new incoming connections is handled in it's own task
				connections.push(tokio::spawn(async move {
					// start listening to new incoming streams
					// in this example we know there is only 1 incoming stream, so we will not wait
					// for more
					let incoming = connection.next().await.expect("no stream found");
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
					let message = receiver.next().await.expect("no message found");
					println!(
						"[server] New message from {}: {}",
						connection.remote_address(),
						message
					);

					// respond
					sender.send(&String::from("hello from server"))?;

					// wait for stream to finish
					sender.finish().await?;
					receiver.finish().await?;

					Result::<_, Error>::Ok(())
				}));
			}

			server.close_incoming().await?;

			// wait for all connections to finish
			let connections = future::try_join_all(connections).await?;

			for connection in connections {
				connection?
			}

			// wait for server to finish cleanly
			server.wait_idle().await;
			println!("[server] Successfully finished {}", server.local_address()?);

			Result::<_, Error>::Ok(())
		})
		.map_err(Error::from)
		.and_then(future::ready)
	});

	// start 100 clients
	for index in 0..CLIENTS {
		let address = address.clone();
		let certificate = certificate.clone();

		tasks.push(
			tokio::spawn(async move {
				// build a client
				let client = Endpoint::new_client()?;
				println!("[client:{}] Bound to {}", index, client.local_address()?);

				let connection = client
					.connect_pinned(address, &certificate)
					.await?
					.accept::<()>()
					.await?;
				connection.close_incoming().await?;
				println!(
					"[client:{}] Successfully connected to {}",
					index,
					connection.remote_address()
				);

				// initiate a stream
				let (sender, mut receiver) = connection.open_stream::<String, String>(&()).await?;
				println!(
					"[client:{}] Successfully opened stream to {}",
					index,
					connection.remote_address()
				);

				// send message
				sender.send(&format!("hello from client {}", index))?;

				// start listening to new incoming messages
				// in this example we know there is only 1 incoming message, so we will not wait
				// for more
				let message = receiver.next().await.expect("no message found");
				println!(
					"[client:{}] New message from {}: {}",
					index,
					connection.remote_address(),
					message
				);

				// wait for stream to finish
				sender.finish().await?;
				receiver.finish().await?;

				// wait for client to finish cleanly
				client.wait_idle().await;
				println!(
					"[client:{}] Successfully finished {}",
					index,
					client.local_address()?
				);

				Result::<_, Error>::Ok(())
			})
			.map_err(Error::from)
			.and_then(future::ready),
		);
	}

	future::try_join_all(tasks).await?;

	Ok(())
}
