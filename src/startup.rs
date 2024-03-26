use crate::{configuration, email_client::EmailClient};
use actix_web::{dev::Server, web, App, HttpServer};
use secrecy::ExposeSecret;
use sqlx::PgPool;
use std::net::TcpListener;
use tracing_actix_web::TracingLogger;

use super::routes::*;

pub fn run(
    listener: TcpListener,
    db_pool: PgPool,
    email_client: EmailClient,
    base_url: String,
) -> Result<Server, std::io::Error> {
    let local_addr = listener.local_addr()?.to_string();
    let db_pool = web::Data::new(db_pool);
    let email_client = web::Data::new(email_client);
    let base_url = web::Data::new(ApplicationBaseUrl(base_url));
    let server = HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .route("/health_check", web::get().to(health_check))
            .route("/subscriptions", web::post().to(subscribe))
            .route("/subscriptions/confirm", web::get().to(confirm))
            .app_data(db_pool.clone())
            .app_data(email_client.clone())
            .app_data(base_url.clone())
    })
    .listen(listener)?
    .run();

    tracing::info!("Server running on {}", local_addr);

    Ok(server)
}

pub struct ApplicationBaseUrl(pub String);

pub struct Application {
    port: u16,
    server: Server,
}

impl Application {
    pub async fn build(configuration: configuration::Settings) -> Result<Self, std::io::Error> {
        let connection_string = configuration.database.connection_string();
        let connection = PgPool::connect(&connection_string.expose_secret())
            .await
            .expect("Failed to connect to Postgres.");

        // Build an `EmailClient` using `configuration`
        let sender_email = configuration
            .email_client
            .sender()
            .expect("Invalid sender email address.");
        let timeout = configuration.email_client.timeout();
        let email_client = EmailClient::new(
            configuration.email_client.base_url,
            sender_email,
            configuration.email_client.authorization_token,
            timeout,
        );

        let address = format!("127.0.0.1:{}", configuration.application.port);
        let listener = TcpListener::bind(address).expect("Failed to bind application port");
        let port = listener.local_addr()?.port();
        let server = run(
            listener,
            connection,
            email_client,
            configuration.application.base_url,
        )?;

        Ok(Self { port, server })
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server.await
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}
