from importlib import import_module


def test_fastapi_app_imports():
    app_module = import_module("main")
    assert hasattr(app_module, "app"), "FastAPI application not found"
