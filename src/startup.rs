use actix_web::{dev::Server, web, App, HttpServer, middleware::Logger};
use sqlx::PgPool;
use std::net::TcpListener;
use super::routes::*;

pub fn run(listener: TcpListener, db_pool: PgPool) -> Result<Server, std::io::Error> {
    let local_addr = listener.local_addr()?.to_string();
    let connection = web::Data::new(db_pool);
    let server = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .route("/health_check", web::get().to(health_check))
            .route("/subscriptions", web::post().to(subscribe))
            .app_data(connection.clone())
    })
    .listen(listener)?
    .run();

    log::info!("Server running on {}", local_addr);

    Ok(server)
}
