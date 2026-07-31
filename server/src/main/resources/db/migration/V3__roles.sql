-- Roles and permissions.
--
-- A permission is a (resource, action) pair rather than a single opaque string. Resources and
-- actions are the two axes every application already thinks in — "may this caller update a
-- material?" — and keeping them separate means a policy can be read and audited without parsing
-- names apart again.

create table role (
    id          uuid        primary key,
    tenant_id   uuid        not null references tenant (id) on delete cascade,
    name        text        not null,
    created_at  timestamptz not null default now(),

    -- Scoped to a tenant: two customers may both have an "Editor" and they must not be the same
    -- row, or editing one tenant's policy would silently rewrite another's.
    constraint role_name_unique_per_tenant unique (tenant_id, name)
);

create table permission (
    role_id   uuid not null references role (id) on delete cascade,
    resource  text not null,
    action    text not null,

    -- Granting the same thing twice is not an error worth reporting, but it must not produce a
    -- duplicate row that makes the effective policy depend on row count.
    constraint permission_unique primary key (role_id, resource, action)
);

create table account_role (
    account_id uuid not null references account (id) on delete cascade,
    role_id    uuid not null references role (id) on delete cascade,

    constraint account_role_pk primary key (account_id, role_id)
);

create index permission_role_idx on permission (role_id);
create index account_role_role_idx on account_role (role_id);
