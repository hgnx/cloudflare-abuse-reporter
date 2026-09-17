# Contributing

Contributions are welcome, especially changes that reduce false positives, improve idempotency, strengthen failure handling, or add deterministic tests.

Before opening a pull request:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip 'setuptools>=68' wheel
python -m pip install -e '.[dev]'
pytest -q
python -m compileall -q spamhaus_reporter
```

Please avoid adding live credentials, real private domains, production logs, or personally identifying data to tests and examples. Use RFC-reserved documentation addresses such as `203.0.113.0/24`, `198.51.100.0/24`, and example domains.

Classifier changes should include tests that demonstrate both the intended detection and a nearby case that should *not* auto-submit.
