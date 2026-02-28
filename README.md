# docker-dns (Go rewrite)

docker-dns watches Traefik routers and keeps Cloudflare DNS A/AAAA records in sync with your WAN IP(s).
It supports Cloudflare API tokens or the global key + email auth.

## Docker image usage

Run (example):

```sh
docker run --rm \
  -e TRAEFIK_API_URL=http://traefik:8080 \
  -e TRAEFIK_ENTRYPOINTS=web,websecure \
  -e CLOUDFLARE_API_TOKEN=your_token_here \
  -e IP_VERSION=both \
  -e DELAY=60 \
  saltydk/dns
```

If you use a global API key:

```sh
docker run --rm \
  -e TRAEFIK_API_URL=http://traefik:8080 \
  -e TRAEFIK_ENTRYPOINTS=web,websecure \
  -e CLOUDFLARE_API_KEY=your_key_here \
  -e CLOUDFLARE_EMAIL=your_email_here \
  saltydk/dns
```

Print version metadata:

```sh
docker run --rm saltydk/dns --version
```

## Environment variables

| Name | Required | Default | Description |
| --- | --- | --- | --- |
| `TRAEFIK_API_URL` | Yes | | Traefik API base URL (e.g., `http://traefik:8080`). |
| `TRAEFIK_ENTRYPOINTS` | Yes | | Comma-separated list of entrypoints to watch (e.g., `web,websecure`). |
| `CLOUDFLARE_API_TOKEN` | Yes* | | Cloudflare API token. Required unless using key+email. |
| `CLOUDFLARE_API_KEY` | Yes* | | Cloudflare global API key. Required with `CLOUDFLARE_EMAIL` if not using a token. |
| `CLOUDFLARE_EMAIL` | Yes* | | Cloudflare account email. Required with `CLOUDFLARE_API_KEY` if not using a token. |
| `CLOUDFLARE_PROXY_DEFAULT` | No | `false` | Default proxied value when creating records. |
| `CUSTOM_URLS` | No | | Comma-separated hostnames to manage in addition to Traefik routers. |
| `IP_VERSION` | No | `both` | `4`, `6`, or `both`. |
| `DELAY` | No | `60` | Loop delay in seconds. Must be > 0. |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, `error`. |
| `WANIP_TIMEOUT` | No | `5` | WAN IP request timeout in seconds. Must be > 0. |
| `WANIP_RETRIES` | No | `3` | WAN IP retries. Must be > 0. |
| `WANIP_RETRY_DELAY` | No | `5` | WAN IP retry delay in seconds. Must be > 0. |
| `CF_RETRY_ATTEMPTS` | No | `3` | Cloudflare retry attempts. Must be > 0. |
| `CF_RETRY_MIN_DELAY` | No | `4` | Cloudflare retry minimum delay in seconds. Must be > 0. |
| `CF_RETRY_MAX_DELAY` | No | `10` | Cloudflare retry maximum delay in seconds. Must be > 0. |

## Behavior summary

- Waits 10 seconds before first sync.
- Fetches Traefik routers with pagination and extracts ``Host(`...`)`` rules.
  - Supports multiple hosts in a single ``Host(`...`)`` clause.
- Filters routers by `TRAEFIK_ENTRYPOINTS`.
- Resolves root domain via public suffix list.
- Loads Cloudflare DNS records per zone and caches zone lists.
  - Refreshes zone list on cache miss or record list error.
- Creates/updates A/AAAA records to match WAN IP(s).
- Deletes CNAME records that conflict with A/AAAA records.
- Removes A/AAAA records for managed hosts when IPv4/IPv6 is disabled (`IP_VERSION=6`/`4`).
- Keeps existing A/AAAA records when routers disappear.
- Logs changes and retries failed Cloudflare operations.

## Cloudflare permissions

If using a token, it must include:

- Zone:Read
- DNS:Edit

## Notes and limitations

- Only Host(...) rules are parsed; other rule styles are ignored.
- Multiple A/AAAA/CNAME records for the same host are treated as an error.
