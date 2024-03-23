-- Add up migration script here

create table if not exists subscription_tokens(
  subscription_token text not null,
  subscriber_id uuid not null references subscriptions (id),
  primary key (subscription_token)
);
