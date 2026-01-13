# -*- coding: utf-8 -*-
try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:  # pragma: no cover
    try:
        from importlib_metadata import version, PackageNotFoundError
    except ImportError:  # pragma: no cover
        version = None
        PackageNotFoundError = Exception


try:
    # Change here if project is renamed and does not equal the package name
    dist_name = 'aleph-nuls2'
    __version__ = version(dist_name)
except (PackageNotFoundError, TypeError):
    __version__ = 'unknown'
finally:
    del version, PackageNotFoundError
