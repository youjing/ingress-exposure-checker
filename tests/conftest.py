import pytest

@pytest.fixture
def sample_targets():
    from iec.models import Target
    return [
        Target(url="http://grafana.example.com", name="grafana-prod"),
        Target(url="http://es.example.com:9200"),
        Target(url="https://nacos.internal.example.com/nacos"),
    ]
