# file-site

A lightweight, self-hosted file sharing web app. Point it at a directory and go.

![Go](https://img.shields.io/badge/Go-stdlib_only-00ADD8) ![Image Size](https://img.shields.io/badge/image-~22MB-green)

## Features

- **Drag & drop** or click to upload with progress tracking
- **File browser** with breadcrumb navigation and folder-first sorting
- **Download** individual files or entire folders as ZIP
- **Create folders** inline from the browser
- **Delete** files and folders with confirmation
- **Optional master password** via environment variable
- **Dark theme** modern UI — single embedded HTML file, no frameworks
- **Zero external dependencies** — Go standard library only
- **~22MB Docker image** (alpine-based)

## Quick Start

```bash
docker compose up -d
```

Open [http://localhost:8080](http://localhost:8080). Files are served from `./data/`.

## Configuration

All configuration is done through environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `/data` | Directory to serve inside the container |
| `PORT` | `8080` | Listen port |
| `MASTER_PASSWORD` | *(unset)* | If set, requires password to access the site |
| `MAX_UPLOAD_SIZE` | `10737418240` | Max upload size in bytes (default 10GB) |

### Enable password protection

Uncomment the line in `docker-compose.yml`:

```yaml
environment:
  - DATA_DIR=/data
  - MASTER_PASSWORD=changeme
```

### Custom data directory

Mount any host path to the container's data dir:

```yaml
volumes:
  - /path/to/your/files:/data
```

## Security

- Path traversal protection on all endpoints
- Constant-time password comparison
- Brute-force delay on failed login attempts
- HttpOnly, SameSite=Strict session cookies (24h expiry)
- No SSL — use a reverse proxy (nginx, Caddy, Traefik) for HTTPS if needed

## Building from source

```bash
go build -o fileshare .
DATA_DIR=./data ./fileshare
```

## License

MIT
