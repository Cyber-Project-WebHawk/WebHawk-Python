import uuid
import requests
from repository.backend_repository import (
    register_backend,
    get_backend_by_api_key,
    get_backends_by_user,
    update_backend_status,
)


def create_backend(name, target_url, user_id):
    """
    Fix #4: backends are now created under the authenticated caller's
    account. Fix #9: name collisions (for this same owner) are reported
    back as a clean error instead of silently allowed.
    """
    api_key = str(uuid.uuid4())
    row, error = register_backend(name, target_url, api_key, user_id)

    if error == "duplicate_name":
        return None, "A backend with this name already exists on your account"
    if error == "duplicate_key":
        return None, "Could not generate a unique API key, please try again"

    return {
        "id": row[0],
        "name": row[1],
        "target_url": row[2],
        "api_key": row[3],  # shown once, at creation time only - see list_backends
        "is_active": row[4],
    }, None


def list_backends(user_id):
    """
    Fix #4: scoped to the caller's own backends. The API key is
    intentionally omitted here - it is only ever returned once, in the
    response to create_backend(), the same way most SaaS platforms only
    show a freshly-generated secret/token a single time.
    """
    rows = get_backends_by_user(user_id)
    return [
        {
            "id": r[0],
            "name": r[1],
            "target_url": r[2],
            "is_active": r[4],
        }
        for r in rows
    ]


def activate_backend(api_key, user_id):
    row = update_backend_status(api_key, is_active=True, user_id=user_id)
    if row is None:
        return None
    return {"id": row[0], "name": row[1], "is_active": row[2]}


def deactivate_backend(api_key, user_id):
    row = update_backend_status(api_key, is_active=False, user_id=user_id)
    if row is None:
        return None
    return {"id": row[0], "name": row[1], "is_active": row[2]}


def proxy_request(api_key, method, path, headers, body, query_params):
    """
    Fix #2: every outbound call is now wrapped so that an unreachable
    backend, a timeout, or a backend that returns a non-JSON response
    (e.g. a plain 404 HTML page, or a redirect) produces a clean JSON
    error instead of an unhandled exception + a full debugger page.
    """
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

    try:
        response = requests.request(
            method=method,
            url=target_url,
            headers=forwarded_headers,
            json=body if body else None,
            params=query_params,
            timeout=10,
        )
    except requests.exceptions.ConnectionError:
        return {"error": "Could not reach the target backend"}, 502
    except requests.exceptions.Timeout:
        return {"error": "The target backend took too long to respond"}, 504
    except requests.exceptions.RequestException:
        return {"error": "Error forwarding the request to the target backend"}, 502

    try:
        response_data = response.json()
    except ValueError:
        # Upstream didn't return valid JSON (HTML error page, plain text,
        # a redirect, a file download, etc.) - degrade gracefully instead
        # of crashing on response.json().
        response_data = {
            "note": "Target backend did not return JSON; raw response included below.",
            "content_type": response.headers.get("Content-Type", "unknown"),
            "raw_response": response.text[:2000],
        }

    return response_data, response.status_code
