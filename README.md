# chokidaar
Chokidaar --- AI-powered Web Application Firewall

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
