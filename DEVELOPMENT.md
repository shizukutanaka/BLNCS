# BLRCS Development Guide

## Development Environment Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv or virtualenv)
- IDE with Python support (VS Code, PyCharm recommended)

### Initial Setup

```bash
# Clone repository
git clone https://github.com/shizukutanaka/BLRCS.git
cd BLRCS

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Linux/Mac:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install development dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install
```

## Project Structure

```
BLRCS/
├── blrcs/                 # Main package directory
│   ├── __init__.py       # Package initialization
│   ├── config.py         # Configuration management
│   ├── database.py       # Database operations
│   ├── cache.py          # Caching implementation
│   ├── auth.py           # Authentication
│   ├── api.py            # API endpoints
│   └── ...               # Other modules
├── tests/                # Test directory
│   ├── unit/            # Unit tests
│   ├── integration/     # Integration tests
│   └── fixtures/        # Test fixtures
├── docs/                 # Documentation
├── scripts/              # Utility scripts
├── requirements.txt      # Production dependencies
├── requirements-dev.txt  # Development dependencies
├── setup.py             # Package setup
├── pyproject.toml       # Project configuration
└── .env.sample          # Environment variables template
```

## Coding Standards

### Style Guide

We follow PEP 8 with the following specifications:
- Line length: 100 characters
- Indentation: 4 spaces
- String quotes: Double quotes preferred

### Type Hints

All functions should include type hints:

```python
from typing import List, Optional, Dict, Any

def process_data(
    input_data: List[Dict[str, Any]], 
    validate: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Process input data and return results.
    
    Args:
        input_data: List of data dictionaries
        validate: Whether to validate input
        
    Returns:
        Processed data dictionary or None if invalid
    """
    pass
```

### Docstrings

Use Google-style docstrings:

```python
def calculate_metrics(data: List[float], threshold: float) -> Dict[str, float]:
    """Calculate statistical metrics from data.
    
    Args:
        data: List of numerical values
        threshold: Minimum threshold for filtering
        
    Returns:
        Dictionary containing calculated metrics
        
    Raises:
        ValueError: If data is empty or threshold is negative
        
    Example:
        >>> calculate_metrics([1.0, 2.0, 3.0], 1.5)
        {'mean': 2.0, 'filtered_count': 2}
    """
    pass
```

## Testing

### Test Structure

```python
import pytest
from unittest.mock import Mock, patch

class TestDatabaseOperations:
    """Test database operations."""
    
    @pytest.fixture
    def db_connection(self):
        """Fixture for database connection."""
        return Mock()
    
    def test_insert_record(self, db_connection):
        """Test inserting a record."""
        # Arrange
        record = {"id": 1, "name": "test"}
        
        # Act
        result = insert_record(db_connection, record)
        
        # Assert
        assert result is True
        db_connection.insert.assert_called_once_with(record)
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=blrcs --cov-report=html

# Run specific test file
pytest tests/unit/test_database.py

# Run tests matching pattern
pytest -k "test_security"

# Run with verbose output
pytest -v

# Run tests in parallel
pytest -n auto
```

### Test Categories

1. **Unit Tests**: Test individual functions/methods
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Test system performance

## Development Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

Follow the coding standards and ensure all tests pass.

### 3. Run Quality Checks

```bash
# Format code
black blrcs/

# Check linting
ruff check blrcs/

# Type checking
mypy blrcs/

# Run tests
pytest
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add new feature description"
```

Commit message format:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `style:` Formatting
- `refactor:` Code restructuring
- `test:` Test additions/changes
- `chore:` Maintenance tasks

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

## Debugging

### Using pdb

```python
import pdb

def complex_function(data):
    # Set breakpoint
    pdb.set_trace()
    
    result = process_data(data)
    return result
```

### Logging

```python
import logging

logger = logging.getLogger(__name__)

def process_request(request):
    logger.debug(f"Processing request: {request.id}")
    
    try:
        result = handle_request(request)
        logger.info(f"Request {request.id} processed successfully")
        return result
    except Exception as e:
        logger.error(f"Error processing request {request.id}: {e}")
        raise
```

### Performance Profiling

```python
import cProfile
import pstats

def profile_function():
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Code to profile
    expensive_operation()
    
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(10)
```

## Database Development

### Migrations

```bash
# Create new migration
alembic revision -m "add_user_table"

# Apply migrations
alembic upgrade head

# Rollback one migration
alembic downgrade -1
```

### Database Schema

```python
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
```

## API Development

### Adding New Endpoint

```python
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

class ItemRequest(BaseModel):
    name: str
    description: str

class ItemResponse(BaseModel):
    id: int
    name: str
    created_at: datetime

@router.post("/items", response_model=ItemResponse)
async def create_item(item: ItemRequest):
    """Create a new item."""
    try:
        result = await database.create_item(item.dict())
        return ItemResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

## Security Considerations

### Input Validation

```python
from pydantic import BaseModel, validator

class UserInput(BaseModel):
    username: str
    email: str
    
    @validator('username')
    def validate_username(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v
    
    @validator('email')
    def validate_email(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v
```

### SQL Injection Prevention

```python
# Bad - vulnerable to SQL injection
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# Good - parameterized query
query = "SELECT * FROM users WHERE name = ?"
cursor.execute(query, (user_input,))
```

## Performance Optimization

### Caching

```python
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_calculation(n: int) -> int:
    """Cache results of expensive calculations."""
    return sum(i ** 2 for i in range(n))
```

### Async Operations

```python
import asyncio

async def fetch_data(url: str) -> dict:
    """Fetch data asynchronously."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()

async def fetch_multiple(urls: List[str]) -> List[dict]:
    """Fetch multiple URLs concurrently."""
    tasks = [fetch_data(url) for url in urls]
    return await asyncio.gather(*tasks)
```

## Documentation

### Code Documentation

- All public functions must have docstrings
- Complex logic should include inline comments
- README files for each major module

### API Documentation

API documentation is auto-generated using OpenAPI:

```bash
# Generate API documentation
python -m blrcs.api_documentation_generator

# View documentation
open http://localhost:8000/docs
```

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure virtual environment is activated
   - Check PYTHONPATH settings
   - Verify package installation

2. **Database Connection Issues**
   - Check DATABASE_URL in .env
   - Verify database server is running
   - Check network connectivity

3. **Test Failures**
   - Clear test cache: `pytest --cache-clear`
   - Check for environment dependencies
   - Verify test fixtures

### Getting Help

- Check existing issues on GitHub
- Review documentation
- Ask in development chat
- Create detailed bug reports

## Release Process

### Version Numbering

Follow Semantic Versioning (MAJOR.MINOR.PATCH):
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

### Release Checklist

1. Update version in `__init__.py`
2. Update CHANGELOG.md
3. Run full test suite
4. Create git tag
5. Build distribution packages
6. Upload to package repository

```bash
# Build packages
python setup.py sdist bdist_wheel

# Upload to PyPI (if applicable)
twine upload dist/*
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - uses: actions/setup-python@v2
      with:
        python-version: '3.8'
    - run: pip install -e .[dev]
    - run: pytest
    - run: black --check blrcs/
    - run: ruff check blrcs/
    - run: mypy blrcs/
```

## Best Practices

1. **Write tests first** (TDD approach)
2. **Keep functions small** and focused
3. **Use meaningful variable names**
4. **Handle errors gracefully**
5. **Document edge cases**
6. **Review your own code** before PR
7. **Keep dependencies minimal**
8. **Use async where appropriate**
9. **Profile before optimizing**
10. **Security first** mindset