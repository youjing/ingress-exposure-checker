from .base import PLUGINS, MiddlewarePlugin, get_plugin, register  # noqa: F401

# Import all plugins so @register fires and populates PLUGINS
from . import (
    grafana, rabbitmq, nacos, elasticsearch,
    prometheus, alertmanager, logstash, kibana, jenkins,
    harbor, nexus, minio, phpmyadmin, tomcat, mongo_express, jfrog,
    druid, kafkaui, phpinfo, unknown, chirpstack,
)
