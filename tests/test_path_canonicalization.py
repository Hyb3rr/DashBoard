import pytest

from app.core.path_canonicalization import canonicalize_path


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/wp-login.php?redirect=/admin", "/wp-login.php"),
        ("//api///users//42//", "/api/users/{id}/"),
        (
            "/orders/550e8400-e29b-41d4-a716-446655440000/items/17",
            "/orders/{uuid}/items/{id}",
        ),
        ("/download/0123456789abcdef?token=secret", "/download/{hash}"),
        ("/Admin/Users", "/Admin/Users"),
        ("/wp-admin/", "/wp-admin/"),
        ("", ""),
    ],
)
def test_canonicalize_path(raw, expected):
    assert canonicalize_path(raw) == expected


def test_query_string_does_not_change_canonical_path():
    assert canonicalize_path("/search?q=one") == canonicalize_path("/search?q=two")


def test_non_dynamic_existing_path_stays_unchanged():
    assert canonicalize_path("/.env") == "/.env"
