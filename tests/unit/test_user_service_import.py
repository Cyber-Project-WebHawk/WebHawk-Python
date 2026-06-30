import importlib


def test_user_service_imports_on_case_sensitive_filesystems():
    module = importlib.import_module("Service.user_service")
    assert callable(module.register_user)
