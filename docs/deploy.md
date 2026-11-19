# Deploying warden (Docker, homelab)

Assumes Docker with the compose plugin, a reverse proxy that terminates HTTPS, and a public hostname (`warden.example.com`) with an **A record** (claude.ai connectors are IPv4-only and the name must not resolve to a private IP).

## 1. Get the files

```sh
mkdir warden && cd warden
curl -O https://raw.githubusercontent.com/Jacob-Tate/warden/main/docker-compose.yml
curl -o .env https://raw.githubusercontent.com/Jacob-Tate/warden/main/.env.example
chmod 600 .env
```

(Or clone the repo and uncomment `build: .` in `docker-compose.yml`.)

## 2. Configure `.env`

`WARDEN_DB_PATH` and `WARDEN_BIND` are fixed by the compose file; ignore them in `.env`.

Generate an API key (printed once; keep the key, put the entry in `.env`):

```sh
docker run --rm ghcr.io/jacob-tate/warden hash-key claude-code
# WARDEN_API_KEYS=claude-code:<sha256hex>
```

Optional, for claude.ai (OAuth consent page). Reads the passphrase from the terminal:

```sh
docker run --rm -it ghcr.io/jacob-tate/warden hash-passphrase
```

Put the hash in `.env` in **single quotes** (it contains `$`):

```
WARDEN_OWNER_PASSPHRASE_HASH='$argon2id$v=19$m=...'
```

Run `docker compose config` and check the hash comes out unmangled. In a compose `environment:` block you would need `$$` instead.

Then set:

```
WARDEN_PUBLIC_URL=https://warden.example.com
WARDEN_TRUSTED_PROXIES=172.18.0.0/16        # the proxy's address as warden sees it
NVD_API_KEY=                                # optional: 50 instead of 5 requests / 30 s
```

`WARDEN_PUBLIC_URL` is used for OAuth metadata and links; it must match the URL clients use. `WARDEN_TRUSTED_PROXIES` takes IPs/CIDRs of the proxy; without it every client looks like the proxy to the rate limiters. With the default `127.0.0.1:8080` port mapping and a proxy on the host, warden sees the Docker bridge gateway (commonly `172.17.0.1`; check `docker network inspect`) rather than 127.0.0.1.

## 3. Start

```sh
docker compose up -d
docker compose ps                # wait for "healthy"
curl -s localhost:8080/healthz   # {"status":"ok"}  ("stale" until the first sync finishes)
docker compose logs -f warden
```

The container runs as uid 10001 with a read-only root filesystem; state lives in the `warden-data` volume (`/data`), and feed downloads are spooled to a tmpfs `/tmp`.

## 4. Reverse proxy

Requirements (MCP streamable HTTP): forward the original `Host` (warden rejects unknown hosts with `403 Forbidden: Host header is not allowed`), forward `X-Forwarded-For`, disable response buffering, and use long read timeouts (a 60 s default kills idle SSE streams). Keep `/mcp`, `/token`, `/register` and `/.well-known/*` reachable from Anthropic's ranges; `/authorize` is opened by your own browser.

### nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name warden.example.com;
    # ssl_certificate ...;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### Caddy

```
warden.example.com {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

Caddy preserves Host and sets `X-Forwarded-For` by default.

### Traefik (Docker labels, proxy on a shared network)

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.warden.rule=Host(`warden.example.com`)
  - traefik.http.routers.warden.entrypoints=websecure
  - traefik.http.routers.warden.tls.certresolver=letsencrypt
  - traefik.http.services.warden.loadbalancer.server.port=8080
```

Traefik does not buffer responses by default (do not add a `buffering` middleware). Raise the entrypoint timeouts in the static config:

```yaml
entryPoints:
  websecure:
    address: ":443"
    transport:
      respondingTimeouts:
        readTimeout: 3600s
        idleTimeout: 3600s
```

Traefik forwards `Host` and `X-Forwarded-For` by default. Set `WARDEN_TRUSTED_PROXIES` to the Traefik container's network subnet.

If Cloudflare or another CDN is in front, prefer DNS-only (CDNs buffer and have idle timeouts), and do not let a WAF 403 `/.well-known/*` or strip `WWW-Authenticate`; that shows up as "Couldn't reach the MCP server".

## 5. Connect clients

Claude Code (API key; the key you generated, not the hash):

```sh
claude mcp add --transport http warden https://warden.example.com/mcp \
  --header "Authorization: Bearer <api-key>"
```

claude.ai (needs `WARDEN_OWNER_PASSPHRASE_HASH`): Settings > Connectors > Add custom connector, URL `https://warden.example.com/mcp`. You are redirected to warden's consent page; enter the owner passphrase to approve. Connectors added in claude.ai are also available to cloud sessions and routines; servers added with `claude mcp add` are not.

## 6. Backups

All state is the SQLite file. The image has no `sqlite3`, so use a throwaway container sharing the volume for an online backup (safe while warden runs):

```sh
docker run --rm -v warden_warden-data:/data -v "$PWD":/backup debian:bookworm-slim \
  sh -c 'apt-get update -qq && apt-get install -y -qq sqlite3 >/dev/null && sqlite3 /data/warden.db ".backup /backup/warden-$(date +%F).db"'
```

The volume name is `<project>_warden-data`; check `docker volume ls`. Alternatively stop and copy: `docker compose stop warden`, copy the volume contents (including any `-wal`/`-shm` files), `docker compose start warden`. Restore by stopping, replacing `/data/warden.db` (owner uid 10001), and starting. CVE data is re-derivable from public feeds, but acks and OAuth tokens are not.

## 7. Upgrading

```sh
docker compose pull && docker compose up -d
docker image prune -f
```

Migrations run on start. Pin a tag (`ghcr.io/jacob-tate/warden:v0.1.0` or `:sha-abc1234`) instead of `latest` for controlled upgrades, and back up first.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `403 Forbidden: Host header is not allowed` | The proxy is not forwarding the original `Host`, or `WARDEN_PUBLIC_URL` does not match the hostname clients use. |
| `401` on `/mcp` | Missing or wrong bearer token. Use the key printed by `hash-key`, not the hash. The log warns when `WARDEN_API_KEYS` is empty. |
| Lockouts / rate limits hit everyone | `WARDEN_TRUSTED_PROXIES` unset or wrong; all clients appear as the proxy. |
| claude.ai "Couldn't reach the MCP server" | No public A record, hostname resolves privately, WAF blocks `/.well-known/*`, or the proxy strips `WWW-Authenticate`. |
| Consent page 404 | `WARDEN_OWNER_PASSPHRASE_HASH` unset (OAuth disabled) or `$` mangled; use single quotes. |
| `/healthz` says `stale` | A core source (cvelist, KEV) is out of date: no sync yet, or egress blocked. Check logs; run `docker compose exec warden warden sync-once`. |
| Container unhealthy / 503 | Database unreachable: `/data` must be writable by uid 10001 and have free space. |
| Streams cut after about 60 s | Proxy read timeout too low or buffering on. |
