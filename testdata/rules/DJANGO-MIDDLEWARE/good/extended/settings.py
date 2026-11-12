from .base import MIDDLEWARE as BASE_MIDDLEWARE

MIDDLEWARE = BASE_MIDDLEWARE + [
    "debug_toolbar.middleware.DebugToolbarMiddleware",
]
