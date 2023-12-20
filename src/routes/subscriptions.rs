use actix_web::{web::Form, HttpResponse, Responder};

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SubscribeRequest {
    email: String,
    name: String,
}

pub async fn subscribe(_form: Form<SubscribeRequest>) -> impl Responder {
    dbg!(_form);
    HttpResponse::Ok()
}
