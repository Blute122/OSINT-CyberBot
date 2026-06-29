"""
pytest configuration.

This file's mere presence at the repository root puts the root on sys.path
during test collection, so the tests can `import cyber_agent` / `scoring` /
`semantic` / `entity_model` regardless of how pytest is invoked (the bare
`pytest` console script does not add the CWD to sys.path the way
`python -m pytest` does).
"""
