"""Shared pagination utilities for list endpoints."""

from typing import Any
from fastapi import Query


class PaginationParams:
    """Dependency for paginated endpoints."""
    def __init__(
        self,
        page: int = Query(1, ge=1, description="Page number"),
        per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    ):
        self.page = page
        self.per_page = per_page
        self.offset = (page - 1) * per_page


def paginated_response(items: list, total: int, page: int, per_page: int) -> dict:
    """Standard paginated response envelope."""
    return {
        "items": items,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page if per_page else 0,
            "has_next": page * per_page < total,
            "has_prev": page > 1,
        }
    }
