import uuid
import requests
from Repository.backend_repository import (
    register_backend,
    get_backend_by_api_key,
    update_backend_status,
    get_all_backends,
)


def create_backend(name, target_url):
    api_key = str(uuid.uuid4())
    row = register_backend(name, target_url, api_key)
    return {
        "id": row[0],
        "name": row[1],
        "target_url": row[2],
        "api_key": row[3],
        "is_active": row[4],
    }


def deactivate_backend(api_key):
    row = update_backend_status(api_key, is_active=False)
    if row is None:
        return None
    return {"id": row[0], "name": row[1], "is_active": row[2]}


def activate_backend(api_key):
    row = update_backend_status(api_key, is_active=True)
    if row is None:
        return None
    return {"id": row[0], "name": row[1], "is_active": row[2]}


def list_backends():
    rows = get_all_backends()
    return [
        {
            "id": r[0],
            "name": r[1],
            "target_url": r[2],
            "api_key": r[3],
            "is_active": r[4],
        }
        for r in rows
    ]


def proxy_request(api_key, method, path, headers, body, query_params):
    backend = get_backend_by_api_key(api_key)

    if backend is None:
        return {"error": "Unknown API key"}, 401

    if not backend[4]:  # is_active
        return {"error": "Backend is disabled"}, 403

    target_url = backend[2].rstrip("/") + "/" + path.lstrip("/")

    forwarded_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in ("host", "content-length")
    }

    response = requests.request(
        method=method,
        url=target_url,
        headers=forwarded_headers,
        json=body if body else None,
        params=query_params,
        timeout=10,
    )

    try:
        return response.json(), response.status_code
    except Exception:
        return {"error": "Backend returned a non-JSON response"}, 502
