import httpx
import pytest

from tests.proxy_fakes import GZIPPED, proxy_client

pytestmark = pytest.mark.anyio


@pytest.fixture
async def client():
    async with proxy_client() as c:
        yield c


async def test_forwards_method_path_query_body_and_headers(client):
    r = await client.request("PATCH", "/api/items/7?page=2&sort=price", content=b'{"qty": 2}',
                             headers={"x-custom": "kept", "content-type": "application/json"})
    seen = r.json()
    assert seen["method"] == "PATCH"
    assert seen["raw_path"] == "/api/items/7"
    assert seen["query"] == "page=2&sort=price"
    assert seen["body"] == '{"qty": 2}'
    assert seen["headers"]["x-custom"] == "kept"
    assert seen["headers"]["host"] == "upstream.test"


async def test_root_and_unusual_methods_are_forwarded(client):
    assert (await client.get("/")).json()["raw_path"] == "/"
    assert (await client.request("PROPFIND", "/dav")).json()["method"] == "PROPFIND"


async def test_encoded_path_reaches_upstream_unchanged(client):
    assert (await client.get("/files/a%2Fb%20c")).json()["raw_path"] == "/files/a%2Fb%20c"


async def test_hop_by_hop_headers_are_not_forwarded(client):
    r = await client.get("/", headers={"connection": "x-hop", "x-hop": "1", "te": "trailers"})
    seen = r.json()["headers"]
    assert "x-hop" not in seen and "te" not in seen


async def test_docs_paths_belong_to_upstream(client):
    assert (await client.get("/docs")).json()["raw_path"] == "/docs"
    assert (await client.get("/openapi.json")).json()["raw_path"] == "/openapi.json"


async def test_status_headers_and_repeated_cookies_pass_through(client):
    r = await client.get("/cookies")
    assert r.status_code == 201
    assert r.text == "made"
    assert r.headers["x-upstream"] == "yes"
    assert r.headers.get_list("set-cookie") == ["a=1; Path=/", "b=2; Path=/"]


async def test_compressed_body_is_passed_through_byte_for_byte(client):
    async with client.stream("GET", "/gzip") as r:
        assert r.headers["content-encoding"] == "gzip"
        assert b"".join([chunk async for chunk in r.aiter_raw()]) == GZIPPED


async def test_redirects_are_returned_not_followed(client):
    r = await client.get("/redirect")
    assert r.status_code == 302 and r.headers["location"] == "/elsewhere"


async def test_upstream_errors_pass_through(client):
    r = await client.get("/broken")
    assert r.status_code == 500 and r.text == "upstream failed"


def _failing(exc):
    def handler(request):
        raise exc("boom", request=request)
    return httpx.MockTransport(handler)


@pytest.mark.parametrize("exc, status", [(httpx.ConnectError, 502), (httpx.ReadTimeout, 504)])
async def test_unreachable_upstream(exc, status):
    async with proxy_client(transport=_failing(exc)) as c:
        r = await c.get("/")
    assert r.status_code == status
    assert "protected site" in r.text
