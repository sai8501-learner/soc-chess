import importlib


spark_module = importlib.import_module("backend.spark_engine.spark_manager")


def test_spark_status_is_degraded_when_initialization_fails(monkeypatch):
    monkeypatch.setattr(spark_module, "_spark_available", False)
    monkeypatch.setattr(spark_module, "_spark_init_error", "Java gateway unavailable")
    monkeypatch.setattr(spark_module.spark_manager, "is_initialized", False)

    status = spark_module.spark_manager.get_status()

    assert status["status"] == "DEGRADED"
    assert status["pyspark_active"] is False
    assert status["initialization_error"] == "Java gateway unavailable"
