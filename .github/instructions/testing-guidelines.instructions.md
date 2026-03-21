---
description: "Use when writing or modifying tests for MCPGuard. Covers pytest patterns, async testing, fixtures, and test structure."
applyTo: "tests/**/*.py"
---

# MCPGuard Testing Guidelines

## Framework
- pytest with `pytest-asyncio` for async tests
- Mark async tests: `@pytest.mark.asyncio`
- Shared fixtures in `tests/conftest.py`

## Test Structure
```python
class TestFeatureName:
    """Tests for feature_name."""
    
    def test_expected_behavior(self):
        """Test that X does Y when Z."""
        # Arrange
        ...
        # Act
        result = function_under_test(...)
        # Assert
        assert result == expected
    
    @pytest.mark.asyncio
    async def test_async_behavior(self):
        """Test async operation."""
        result = await async_function(...)
        assert result is not None
```

## Naming
- Files: `test_<module>.py`
- Classes: `TestClassName`
- Functions: `test_<behavior>_<condition>`

## Commands
```bash
# All tests
python -m pytest tests/ -v --tb=short

# Single file
python -m pytest tests/test_proxy.py -v

# Single test
python -m pytest tests/test_proxy.py::TestProxy::test_name -v
```

## Rules
- Tests must not depend on external services
- Use mocks for I/O — `unittest.mock.AsyncMock` for async
- Each test must be independent and idempotent
- Target: all 106+ existing tests must continue to pass
