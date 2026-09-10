# S360 Vector Health

Health diagnostics for a Drupal AI site's external vector store. Answers three
questions that are otherwise guesswork from inside a container: can the site
reach the store and is the connection verified, which Search API index is
pointed at which collection, and (on Pantheon) what egress address the
container presents to the store's firewall.

## What it gives you

1. **Status report rows** (`/admin/reports/status`): the vector store
   connection (error when unreachable, warning when reachable but the
   certificate is not verified, OK otherwise) and one row per Search API
   server using the configured provider with its database, collection, and
   attached indexes.
2. **`drush s360:vector:health`**: the same facts as a table, plus the egress
   section where it applies. `--format=json` for scripts.
3. **`/admin/reports/vector-health`** (permission *Use the vector store health
   report*, restricted; denied on live by default): connection settings with
   credentials excluded, reachability, negotiated TLS from `pg_stat_ssl`,
   whether the SSL mode in force verifies the server, index targets, and the
   egress section.

## The egress section (Pantheon)

Pantheon publishes no egress range. A store behind an IP allowlist has to allow
the published Google Cloud prefixes containers have been seen in, and a
container that moves outside them fails as a plain connection timeout. The
report shows the container's current address, looks it up in Google's
published range list (cached a day), and prefills a firewall rule for the whole
prefix from a template you set in settings. It defaults to an Azure Database
for PostgreSQL rule; replace the template for other stores. Tokens:
`{rule_name}`, `{start}`, `{end}`, `{ip}`, `{prefix}`.

The section shows automatically where `PANTHEON_ENVIRONMENT` is set, and can be
forced on or off. It stops mattering once the store is reached over a private
path (for example Pantheon Secure Integration); turn it off then.

## Provider

The connection is asked from the Drupal AI vector DB provider named in
settings (default `postgres`). Any provider that returns connection data with
`host`, `port`, `default_database`, `sslmode`, and `sslrootcert`, and a
PDO-style connection, works; the TLS detail comes from `pg_stat_ssl`, so it is
Postgres-shaped.

## Install

```
composer require square360/s360_vector_health
drush en s360_vector_health
```

Requires `drupal/ai` and `drupal/search_api`. Settings at
`/admin/config/system/vector-health`. Grant *Use the vector store health
report* to the roles that should see the page; the status report and the drush
command need nothing extra.

## Read-only

Nothing here writes to the store, the index, or the firewall. The firewall
command is text to copy; running it is a human decision.
