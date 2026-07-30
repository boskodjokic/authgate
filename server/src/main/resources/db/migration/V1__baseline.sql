-- Baseline schema: who exists, and which external identities map onto them.
--
-- Deliberately no password column, and there will not be one. AuthGate authenticates by
-- federation or by emailed link; there is no credential here to leak.

create table tenant (
    id          uuid        primary key,
    slug        text        not null unique,
    name        text        not null,
    active      boolean     not null default true,
    created_at  timestamptz not null default now()
);

create table account (
    id            uuid        primary key,
    tenant_id     uuid        not null references tenant (id),
    email         text        not null,
    display_name  text,
    active        boolean     not null default true,
    superuser     boolean     not null default false,
    created_at    timestamptz not null default now(),

    -- Scoped to the tenant, not global: the same person may hold an account in two tenants, and
    -- one tenant must not be able to squat an address in another.
    constraint account_email_unique_per_tenant unique (tenant_id, email)
);

create table federated_identity (
    id          uuid        primary key,
    account_id  uuid        not null references account (id) on delete cascade,
    issuer      text        not null,
    subject     text        not null,
    created_at  timestamptz not null default now(),

    -- The identity binding, and the reason this table exists at all. An account is reached by
    -- (issuer, subject) — never by email, which is mutable and asserted by whichever provider
    -- answered. Without this pair being the key, two providers that both assert the same address
    -- become interchangeable and one can impersonate the other's users.
    constraint federated_identity_unique unique (issuer, subject)
);

create index federated_identity_account_idx on federated_identity (account_id);
