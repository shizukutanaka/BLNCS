"""Pytest bootstrap for the BLNCS repository.

Ensures the repository root is importable so ``import blncs`` works no
matter which subset of the test tree is selected (e.g. ``pytest
tests/unit/``). Without this, pytest only prepends the test files'
package root to ``sys.path``; because ``tests/unit/`` has no
``__init__.py``, running that directory on its own used to fail
collection with ``ModuleNotFoundError: No module named 'blncs'``.
"""
