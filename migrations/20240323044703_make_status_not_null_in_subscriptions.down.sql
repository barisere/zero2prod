-- Add down migration script here

alter table subscriptions alter column status drop not null;
