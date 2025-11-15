def test_imports():
    import backend.main  # noqa: F401
    from backend.scanners import exposure, headers, sslscan, techdetect  # noqa: F401

    assert exposure is not None
    assert headers is not None
    assert sslscan is not None
    assert techdetect is not None
