from registrata.metrics import MetricsRegistry


def test_metrics_registry_counters_and_observations():
    metrics = MetricsRegistry()
    metrics.add("gateway_request_total", 2, {"path": "/health"})
    metrics.observe("gateway_request_duration_ms", 10, {"path": "/health"})
    metrics.observe("gateway_request_duration_ms", 30, {"path": "/health"})

    snapshot = metrics.snapshot()
    assert snapshot["counters"]["gateway_request_total{path=/health}"] == 2
    observation = snapshot["observations"]["gateway_request_duration_ms{path=/health}"]
    assert observation["count"] == 2
    assert observation["sum"] == 40
    assert observation["min"] == 10
    assert observation["max"] == 30
    assert observation["mean"] == 20
    assert snapshot["uptime_seconds"] >= 0.0
