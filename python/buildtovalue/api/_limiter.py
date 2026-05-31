"""Shared slowapi rate limiter (HIGH-01).

Defined in its own module so both ``app.py`` (edge wiring) and the route
modules (e.g. ``routes/auth.py``) can import the *same* ``Limiter`` instance
without a circular import. The exception handler and ``app.state.limiter``
wiring live in ``app.py``.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

# Per-client limiter keyed by remote address. Per-route limits are applied with
# the ``@limiter.limit(...)`` decorator (e.g. login = 10/minute).
limiter = Limiter(key_func=get_remote_address)
