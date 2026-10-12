import pytest

from iec.models import Target
from iec.plugins.base import PLUGINS

# Capture baseline BEFORE importing the concrete plugin modules, whose
# module-level @register decorators would otherwise mutate PLUGINS for the
# rest of the session. The autouse fixture restores this after each test.
_PLUGINS_BASELINE = list(PLUGINS)

from iec.plugins.elasticsearch import ElasticsearchPlugin
from iec.plugins.grafana import GrafanaPlugin
from iec.plugins.nacos import NacosPlugin
from iec.plugins.rabbitmq import RabbitMQPlugin
from iec.probe import ProbeContext


@pytest.fixture(autouse=True)
def _restore_plugins():
    yield
    PLUGINS[:] = _PLUGINS_BASELINE


class C(ProbeContext):
    def __init__(self, body="", headers=None, favicon=None):
        super().__init__(target=Target(url="http://x"))
        self.home_body = body
        self.home_headers = headers or {}
        self.favicon_hash = favicon


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("<title>Grafana</title>", True),
        ("grafana-app", True),
        ("nothing", False),
    ],
)
async def test_grafana_fingerprint(body, expected):
    p = GrafanaPlugin()
    r = await p.fingerprint(C(body=body))
    assert (r is not None) == expected
    if expected:
        assert r.middleware == "grafana"


@pytest.mark.asyncio
async def test_rabbitmq_fingerprint():
    ctx = C(body="RabbitMQ Management")
    r = await RabbitMQPlugin().fingerprint(ctx)
    assert r.middleware == "rabbitmq"


@pytest.mark.asyncio
async def test_nacos_fingerprint():
    r = await NacosPlugin().fingerprint(C(body="/nacos/v1/"))
    assert r is not None and r.middleware == "nacos"


@pytest.mark.asyncio
async def test_elasticsearch_fingerprint():
    ctx = C(body='{"cluster_name":"test","tagline":"You Know, for Search"}')
    r = await ElasticsearchPlugin().fingerprint(ctx)
    assert r is not None and r.middleware == "elasticsearch"
