#!/usr/bin/env python3
"""
Quality Assurance Tests for BLNCS
Fast, focused tests for code quality verification.
"""

import unittest
import sys
from pathlib import Path
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCodeQuality(unittest.TestCase):
    """Code quality and structure tests"""
    
    def test_core_module_imports(self) -> None:
        """Test that all core modules can be imported without errors"""
        try:
            from blncs.core.exceptions import BLNCSError
            from blncs.core.config import get_config
            from blncs.core.logger import get_logger
            from blncs.core.health import get_health_checker
            from blncs.core.cache import get_cache
        except ImportError as e:
            self.fail(f"Core module import failed: {e}")
    
    def test_lightning_module_imports(self) -> None:
        """Test Lightning Network module imports"""
        try:
            from blncs.lightning.client import LightningClient
        except ImportError as e:
            self.fail(f"Lightning module import failed: {e}")
    
    def test_cli_module_import(self) -> None:
        """Test CLI module import"""
        try:
            from blncs.cli.main import cli
        except ImportError as e:
            self.fail(f"CLI module import failed: {e}")
    
    def test_exception_hierarchy(self) -> None:
        """Test exception class hierarchy"""
        from blncs.core.exceptions import BLNCSError, LightningError, ConnectionError
        
        # Test inheritance
        self.assertTrue(issubclass(LightningError, BLNCSError))
        self.assertTrue(issubclass(ConnectionError, LightningError))
        
        # Test basic functionality
        error = BLNCSError("Test error")
        self.assertEqual(error.message, "Test error")
        self.assertTrue(error.recoverable)  # Default
        
        error_dict = error.to_dict()
        self.assertIsInstance(error_dict, dict)
        self.assertIn("message", error_dict)
    
    def test_config_basic_functionality(self) -> None:
        """Test basic configuration functionality"""
        from blncs.core.config import get_config
        
        config = get_config()
        
        # Test basic structure
        self.assertIsInstance(config.data, dict)
        self.assertIn('lightning', config.data)
        self.assertIn('system', config.data)
        
        # Test get/set operations
        config.set('test.key', 'test_value')
        value = config.get('test.key')
        self.assertEqual(value, 'test_value')
        
        # Test default value
        default = config.get('non.existent', 'default')
        self.assertEqual(default, 'default')
    
    def test_logger_functionality(self) -> None:
        """Test logging system functionality"""
        from blncs.core.logger import get_logger, setup_logger
        
        # Test logger creation
        logger = get_logger("test_logger")
        self.assertIsNotNone(logger)
        
        # Test logger with setup
        setup_logger = setup_logger("test_setup", "INFO", False)
        self.assertIsNotNone(setup_logger)
    
    def test_health_checker_basic(self) -> None:
        """Test health checker basic functionality"""
        from blncs.core.health import get_health_checker
        
        checker = get_health_checker()
        self.assertIsNotNone(checker)
        
        # Test quick status (should not hang)
        status = checker.get_quick_status()
        self.assertIsInstance(status, dict)
        self.assertIn('timestamp', status)
        self.assertIn('status', status)
    
    def test_lightning_client_creation(self) -> None:
        """Test Lightning client creation"""
        from blncs.lightning.client import LightningClient
        
        test_config = {
            'lightning': {
                'host': 'localhost',
                'port': 9999,
                'network': 'testnet'
            }
        }
        
        client = LightningClient(test_config)
        self.assertEqual(client.host, 'localhost')
        self.assertEqual(client.port, 9999)
        self.assertEqual(client.network, 'testnet')
        self.assertFalse(client.connected)


class TestTypeHints(unittest.TestCase):
    """Test type hints and type safety"""
    
    def test_function_type_annotations(self) -> None:
        """Test that key functions have proper type annotations"""
        from blncs.core.config import Config
        from blncs.core.health import HealthChecker
        
        # Check Config class methods have type hints
        config = Config()
        
        # These should have type annotations (check method signatures)
        self.assertTrue(hasattr(config.save, '__annotations__'))
        self.assertTrue(hasattr(config.set, '__annotations__'))
        
        # Check HealthChecker
        checker = HealthChecker()
        self.assertTrue(hasattr(checker.__init__, '__annotations__'))


class TestStructure(unittest.TestCase):
    """Test project structure and organization"""
    
    def test_project_structure(self) -> None:
        """Test that project has proper structure"""
        project_root = Path(__file__).parent.parent
        
        # Check main directories exist
        expected_dirs = [
            'blncs',
            'blncs/core',
            'blncs/lightning',
            'blncs/cli',
            'tests'
        ]
        
        for dir_name in expected_dirs:
            dir_path = project_root / dir_name
            self.assertTrue(dir_path.exists(), f"Directory {dir_name} should exist")
            self.assertTrue(dir_path.is_dir(), f"{dir_name} should be a directory")
    
    def test_init_files(self) -> None:
        """Test that __init__.py files exist where needed"""
        project_root = Path(__file__).parent.parent
        
        expected_init_files = [
            'blncs/__init__.py',
            'blncs/core/__init__.py',
            'blncs/lightning/__init__.py', 
            'blncs/utils/__init__.py',
            'blncs/cli/__init__.py',
            'tests/__init__.py'
        ]
        
        for init_file in expected_init_files:
            init_path = project_root / init_file
            self.assertTrue(init_path.exists(), f"__init__.py should exist at {init_file}")
    
    def test_pyproject_toml(self) -> None:
        """Test pyproject.toml exists and has basic structure"""
        project_root = Path(__file__).parent.parent
        pyproject_path = project_root / 'pyproject.toml'
        
        self.assertTrue(pyproject_path.exists(), "pyproject.toml should exist")
        
        content = pyproject_path.read_text()
        self.assertIn('[project]', content)
        self.assertIn('name = "blncs"', content)


def run_quality_tests() -> bool:
    """Run all quality tests"""
    print("🧪 Running BLNCS Quality Assurance Tests")
    print("=" * 50)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    test_cases = [
        TestCodeQuality,
        TestTypeHints,
        TestStructure,
    ]
    
    for test_case in test_cases:
        tests = loader.loadTestsFromTestCase(test_case)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, failfast=False)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"📊 Quality Test Results:")
    print(f"   Tests run: {result.testsRun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")
    
    success = result.wasSuccessful()
    if success:
        print("✅ All quality tests passed!")
    else:
        print("❌ Some quality tests failed!")
        
        if result.failures:
            print("\n🔥 Failures:")
            for test, traceback in result.failures:
                print(f"   - {test}")
        
        if result.errors:
            print("\n💥 Errors:")
            for test, traceback in result.errors:
                print(f"   - {test}")
    
    return success


if __name__ == '__main__':
    success = run_quality_tests()
    sys.exit(0 if success else 1)