-- Add down migration script here

alter table subscriptions drop column status;
