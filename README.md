# chokidaar
Chokidaar --- AI-powered Web Application Firewall

## Running the executable

On Windows, Chokidaar can run as a single file with no Python install. Point it
at the app to protect and send your traffic to the port it listens on:

```powershell
chokidaar.exe --upstream http://localhost:3000 --port 8080
```

Then open http://localhost:8080. The trained model is packed into the
executable, so it starts without retraining.

| Option | Default | Meaning |
| --- | --- | --- |
| `--upstream URL` | (required) | The app to protect; must start with `http://` or `https://`. |
| `--port N` | `8080` | Port to listen on. |
| `--host ADDR` | `127.0.0.1` | Address to listen on; use `0.0.0.0` to accept connections from other machines. |
| `--mode block\|monitor` | `block` | `block` refuses malicious requests with a reason; `monitor` lets them through and only logs them. |
| `--log-db PATH` | `logs\chokidaar.db` | SQLite file for the request log. |

Run `chokidaar.exe --help` to see the same list. The same entry point works
from source with `python -m proxy.cli --upstream http://localhost:3000`.

### Building it

From the repository root, in a virtual environment:

```powershell
pip install -r requirements-dev.txt
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
```

The script trains the model (`python -m ml.train`) and builds
`dist\chokidaar.exe` with PyInstaller. `build\`, `dist\` and the generated
`chokidaar.spec` are not committed.

## Running with Docker

The compose file starts OWASP Juice Shop as the protected app (reachable only
inside the compose network) and Chokidaar in front of it on port 8080. The
classifier is trained when the image is built, not on every start.

```sh
docker compose up --build
```

Then open http://localhost:8080.

A normal request is passed through to the app:

```sh
curl -i "http://localhost:8080/rest/products/search?q=apple"
# HTTP/1.1 200 OK
```

An SQL injection attempt is blocked with a reason:

```sh
curl -i "http://localhost:8080/rest/products/search?q='%20OR%201=1--"
# HTTP/1.1 403 Forbidden
```

Set `MODE=monitor` to log suspicious requests without blocking them
(`MODE=monitor docker compose up`). The request log is kept at
`/data/chokidaar.db` on the `chokidaar-data` volume.
