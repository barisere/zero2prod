use std::net::TcpListener;
use actix_web::{HttpServer, dev::Server, App, web};

pub fn run(listener: TcpListener) -> Result<Server, std::io::Error> {
    use super::routes::*;
    let server = HttpServer::new(|| {
        App::new()
            .route("/health_check", web::get().to(health_check))
            .route("/subscriptions", web::post().to(subscribe))
    })
    .listen(listener)?
    .run();

    Ok(server)
}
