"""Built-in analyzers — importing this module registers them.

Adding a new analyzer = create the file, decorate with ``@analyzer(...)``,
import it here. The orchestrator picks it up via ``all_analyzers()``.
"""

from __future__ import annotations

# Importing for side-effect (decorator runs).
from wimsalabim.analyzers import dns_recon as _dns_recon  # noqa: F401
from wimsalabim.analyzers import headers as _headers  # noqa: F401
from wimsalabim.analyzers import ports as _ports  # noqa: F401
from wimsalabim.analyzers import tls as _tls  # noqa: F401

__all__: list[str] = []
