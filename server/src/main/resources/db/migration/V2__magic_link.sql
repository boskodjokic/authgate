-- Single-use sign-in tokens.
--
-- The token is stored as a SHA-256 hash, never in the clear. A magic link is a bearer credential
-- for the length of its life, so a leaked database backup or a stray log line must not be enough
-- to sign in as anyone who has a link outstanding.

create table magic_link (
    -- The hash, and the primary key: a lookup is a hash of the presented token, so there is no
    -- path that needs the original value.
    token_hash   text        primary key,
    account_id   uuid        not null references account (id) on delete cascade,
    audience     text        not null,
    expires_at   timestamptz not null,
    -- Set the moment the link is redeemed. A row is kept rather than deleted so that a second
    -- attempt can be told apart from a link that never existed, which is the difference between
    -- a replayed link and a typo.
    consumed_at  timestamptz,
    created_at   timestamptz not null default now()
);

create index magic_link_account_idx on magic_link (account_id);
create index magic_link_expires_idx on magic_link (expires_at);
