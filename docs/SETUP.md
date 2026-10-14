# Setup guide — run it on your PC

Pick **one** path. **Path A (Docker)** needs no C++ toolchain and is the quickest. **Path B (WSL2/Linux)** is for
developing, debugging and running the sanitizers.

---------------------------------------------------------------------------------------------
## Path A — Docker (Windows 10/11, macOS or Linux)

### Tools to install
| Tool | Why | Windows notes |
|---|---|---|
| Virtualization enabled in BIOS | Docker needs it | Task Manager → Performance → CPU → "Virtualization: Enabled". If not, enable *Intel VT-x / AMD SVM* in BIOS |
| WSL2 | Docker Desktop backend | Admin PowerShell: `wsl --install`, reboot |
| Docker Desktop | runs db + gateway + demo | docker.com → Docker Desktop; keep "Use WSL 2" ticked |
| Git | version control (optional for zip) | git-scm.com |
| Python 3.10+ | demo + integration tests | python.org; tick **"Add python.exe to PATH"** |
| VS Code (optional) | editing | extensions: C/C++, CMake Tools, Docker, WSL |

### Steps
```powershell
# 1. get the code
cd C:\Users\<you>\Projects
# unzip zero-trust-gateway.zip here, then:
cd zero-trust-gateway
git init; git add .; git commit -m "Zero Trust Gateway"      # your repo

# 2. secrets
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"      # paste as JWT_SECRET in .env
notepad .env                                                   # also set ADMIN_PASSWORD and DB_PASSWORD (letters+digits)

# 3. build and start (first build downloads dependencies: ~3-8 minutes)
docker compose up --build -d
docker compose ps                                              # gateway should be "healthy"
curl.exe http://localhost:8080/healthz                         # {"status":"ok"}
```
Open **http://localhost:8080/** → sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` → dashboard.

```powershell
# 4. narrated demo (PowerShell syntax; on bash use VAR=value python3 ...)
$env:ADMIN_PASSWORD = "<value from .env>"
python tools\demo.py

# 5. full security test-suite against the container
$env:JWT_SECRET     = "<value from .env>"
$env:ADMIN_EMAIL    = "admin@example.com"
$env:ADMIN_PASSWORD = "<value from .env>"
$env:DEMO_UPSTREAM  = "http://demo:9000"
python tests\integration_test.py -v

# 6. watch logs / stop
docker compose logs -f gateway
docker compose down            # keep data;   add -v to wipe the database
```
Prove the isolation claim yourself: `curl http://localhost:9000/hr` fails (the demo app has **no** published port),
while the same data via `/resources/<id>` works only with a token + policy match.

---------------------------------------------------------------------------------------------
## Path B — native build (WSL2 Ubuntu 22.04/24.04, or any Linux)

### Tools
`build-essential` (g++ ≥ 9), `cmake` ≥ 3.20, `ninja-build`, `git`, `libpq-dev`, `libssl-dev`, `postgresql`,
`python3`, optional `gdb`, `valgrind`, `curl`, `jq`. On Windows: `wsl --install -d Ubuntu-24.04`, then work **inside the
Linux filesystem** (`~/projects`, not `/mnt/c`) — builds are far faster. VS Code → "WSL" extension → *Reopen in WSL*.

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build git libpq-dev libssl-dev postgresql python3 curl gdb

# PostgreSQL
sudo service postgresql start
sudo -u postgres psql -c "CREATE USER zt WITH PASSWORD 'zt';" -c "CREATE DATABASE ztgw OWNER zt;"
PGPASSWORD=zt psql -h 127.0.0.1 -U zt -d ztgw -f db/schema.sql

# build + unit tests
cmake -G Ninja -B build && cmake --build build
./build/unit_tests

# run (two terminals, or use &)
export JWT_SECRET=$(python3 -c "import secrets;print(secrets.token_hex(32))")
export ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='Admin-Password-123!'
export DATABASE_URL=postgresql://zt:zt@127.0.0.1:5432/ztgw
export DEMO_UPSTREAM=http://127.0.0.1:9000 WEB_DIR=$PWD/web
./build/demo_service &
./build/gateway

# in another terminal (same exports for JWT_SECRET/ADMIN_*/DEMO_UPSTREAM)
python3 tools/demo.py
python3 tests/integration_test.py -v
```
**macOS:** `brew install cmake ninja libpq openssl@3 postgresql@16` and add
`-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) -DPostgreSQL_ROOT=$(brew --prefix libpq)` to the first cmake command.

---------------------------------------------------------------------------------------------
## Troubleshooting
| Symptom | Fix |
|---|---|
| `JWT_SECRET must be set and at least 32 characters` | Set it in `.env` (Docker) or `export` it (native) |
| `port is already allocated` (8080) | Change `"8080:8080"` to `"8081:8080"` in compose and use `GATEWAY_URL=http://localhost:8081` |
| Docker build can't download dependencies | Needs access to github.com; retry, or check VPN/proxy/ISP blocks |
| `db connect failed` loops at startup | PostgreSQL not ready / wrong `DATABASE_URL`; the gateway retries for 30 s |
| Tests: many `429` | Per-IP rate limit is working; the tests already back off. Raise `RATE_RPS` for benchmarking |
| Login locked for 5 minutes | Intended (5 failures/account). Restart the gateway to clear in-memory lockouts |
| PowerShell: `VAR=value cmd` doesn't work | Use `$env:VAR="value"` then run the command |
| Password with `@` or `/` breaks DB URL | Keep `DB_PASSWORD` to letters and digits |
