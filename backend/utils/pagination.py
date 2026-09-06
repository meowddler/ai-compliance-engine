"""Pagination.

Unbounded list endpoints are a latent outage: they work fine at development
volume and time out at production volume, and the failure arrives without
warning the day a customer's data crosses the threshold.

Offset pagination is used here rather than cursor pagination. Offsets get slow
at very high page numbers because the database must count rows it will discard,
but they support jumping to an arbitrary page, which the UI needs. At the scale
this system targets the tradeoff favours offsets; cursors are the answer if
result sets reach millions.
"""

from fastapi import Query

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500


class PageParams:
    """Validated pagination inputs.

    The maximum is enforced server-side. A client asking for a million rows is
    either mistaken or hostile, and either way the server should not comply.
    """

    def __init__(
        self,
        page: int = Query(1, ge=1, description="Page number, starting at 1."),
        page_size: int = Query(
            DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE,
            description=f"Rows per page (max {MAX_PAGE_SIZE}).",
        ),
    ):
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def paginate(query, params: PageParams, serializer=None) -> dict:
    """Apply pagination to a SQLAlchemy query and describe the result.

    The total is counted before the limit is applied, so a caller knows how many
    pages exist rather than discovering the end by walking off it.
    """
    total = query.order_by(None).count()
    rows = query.offset(params.offset).limit(params.page_size).all()

    total_pages = (total + params.page_size - 1) // params.page_size if total else 0

    return {
        "items": [serializer(r) for r in rows] if serializer else rows,
        "pagination": {
            "page": params.page,
            "page_size": params.page_size,
            "total_items": total,
            "total_pages": total_pages,
            "has_next": params.page < total_pages,
            "has_previous": params.page > 1,
        },
    }