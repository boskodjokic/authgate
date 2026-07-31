-- Refresh tokens and the access-token denylist.

create table refresh_token (
    -- SHA-256 of the token, never the token itself: it is a long-lived bearer credential, so a
    -- database leak must not be a set of usable sessions.
    token_hash   text        primary key,
    account_id   uuid        not null references account (id) on delete cascade,

    -- Every token descended from one sign-in shares a family id. Rotation issues a new member;
    -- detecting a replay revokes the whole family, because there is no way to tell which holder is
    -- the thief and which is the victim.
    family_id    uuid        not null,

    audience     text        not null,
    expires_at   timestamptz not null,

    -- Set when the token is exchanged. The row is kept rather than deleted: a spent token being
    -- presented again is precisely the signal reuse detection exists to catch, and a deleted row
    -- is indistinguishable from one that never existed.
    consumed_at  timestamptz,

    -- Set when the whole family is withdrawn, by logout or by reuse detection.
    revoked_at   timestamptz,

    created_at   timestamptz not null default now()
);

create index refresh_token_family_idx on refresh_token (family_id);
create index refresh_token_account_idx on refresh_token (account_id);
create index refresh_token_expires_idx on refresh_token (expires_at);

-- Access tokens are self-contained, so withdrawing one before it expires means naming it. This is
-- what the jti claim on every issued token is for.
create table revoked_token (
    jti         text        primary key,
    -- Kept so expired entries can be swept: once the token would have expired anyway, the row is
    -- no longer load-bearing and the table need not grow without bound.
    expires_at  timestamptz not null,
    revoked_at  timestamptz not null default now()
);

create index revoked_token_expires_idx on revoked_token (expires_at);
