# NAS deployment with external MySQL and Redis

This deployment runs four application containers from GHCR:

- `xianyu-frontend` (the only service exposed to the LAN)
- `xianyu-backend-web`
- `xianyu-websocket` (browser automation and login state)
- `xianyu-scheduler`

It intentionally does **not** create MySQL or Redis containers. Use it when those services already exist on the NAS.

## 1. Publish images from the fork

The workflow at `.github/workflows/publish-ghcr.yml` publishes four `linux/amd64` images when `main` is pushed, a `v*` tag is pushed, or the workflow is run manually. It uses the repository-scoped `GITHUB_TOKEN`; no personal access token is stored in Actions.

After the first run, in GitHub open each package's **Package settings** and make it public if the NAS should pull without logging in. If packages remain private, log in on the NAS with a GitHub fine-grained PAT that has only **Packages: Read** access:

```bash
docker login ghcr.io
```

For production, release a tag and use that immutable tag in `IMAGE_TAG`; do not continuously deploy `latest`.

> This workflow builds `linux/amd64`, suitable for Intel/AMD NAS models. ARM NAS support requires testing the Dockerfiles first; then add `docker/setup-qemu-action@v3` and change `platforms` to `linux/amd64,linux/arm64`.

## 2. Prepare MySQL and Redis

Create a dedicated database/user and use a strong password. Example MySQL initialization:

```sql
CREATE DATABASE IF NOT EXISTS xianyu_data
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'xianyu'@'%' IDENTIFIED BY '<strong-password>';
GRANT ALL PRIVILEGES ON xianyu_data.* TO 'xianyu'@'%';
FLUSH PRIVILEGES;
```

Grant only the needed access and restrict it to the Docker/NAS network when possible. Redis must accept connections from the app containers and should require a password. Never expose either service to the public internet.

If MySQL/Redis run on the NAS host and their ports are published locally, use `host.docker.internal` in `.env`. The Compose file maps it to Docker's `host-gateway`.

If they are separate Docker containers without host port publishing, connect this project to their existing external Docker network and use their service/container DNS names instead. Do not use `localhost` or `127.0.0.1` from an app container.

## 3. Deploy from Container Manager or SSH

Copy the following two files into a NAS directory such as `/volume1/docker/xianyu-auto-reply/`:

- `compose.nas-external-db.yml`
- `.env.nas.example`

Rename `.env.nas.example` to `.env`, then set all `CHANGE_ME` values and replace `NAS_LAN_IP`.

In Synology Container Manager, create a **Project** from `compose.nas-external-db.yml` in that directory. Or over SSH:

```bash
cd /volume1/docker/xianyu-auto-reply
docker compose -f compose.nas-external-db.yml --env-file .env pull
docker compose -f compose.nas-external-db.yml --env-file .env up -d
docker compose -f compose.nas-external-db.yml --env-file .env ps
```

Open `http://NAS_LAN_IP:9000`. The default upstream administrator is `admin` / `admin123`; change it immediately.

Only port 9000 is published. The API, WebSocket, scheduler, MySQL, and Redis remain internal to Docker or the NAS.

## 4. Persistent application data and updates

The Compose file stores the following in `./data/` beside the Compose file:

- `browser-data/`: login/cookie/browser state — preserve this or sign-in is required again
- `static/`: uploaded/static files
- `backups/`: application backups
- `logs/`: service logs

Back up `data/` and your MySQL database before updating. To upgrade, change `IMAGE_TAG` to a tested release tag and run:

```bash
docker compose -f compose.nas-external-db.yml --env-file .env pull
docker compose -f compose.nas-external-db.yml --env-file .env up -d
```

Troubleshoot with:

```bash
docker compose -f compose.nas-external-db.yml --env-file .env logs -f
```

## Security and operational notes

- Do not commit `.env` or passwords.
- Keep MySQL/Redis LAN-only or Docker-network-only.
- Use a reverse proxy and HTTPS before exposing the app outside the LAN.
- The project includes browser-driven account automation. Use it only in compliance with the platform's rules, account authorization, and applicable law.
