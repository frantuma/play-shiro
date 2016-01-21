# --- First database schema

# --- !Ups

create table user_roles (
  user_name         varchar(30) not null,
  role_name         varchar(30) not null,
  primary key (user_name, role_name)
);

create table user_permissions (
  user_name         varchar(30) not null,
  permission_name         varchar(100) not null,
  primary key (user_name, permission_name)
);

# --- !Downs

drop table if exists user_roles;
drop table if exists user_permissions;
