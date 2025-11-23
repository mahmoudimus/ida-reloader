"""Unit tests for reload_package function."""
import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, call

from ida_reloader import reload_package


class TestReloadPackage(unittest.TestCase):
    """Test cases for reload_package function."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test packages
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove test modules from sys.modules
        to_remove = [key for key in sys.modules.keys() if key.startswith('test_reload_pkg')]
        for key in to_remove:
            del sys.modules[key]

        # Clean up temporary directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def create_test_package(self, name="test_reload_pkg"):
        """Create a test package with some modules."""
        pkg_dir = self.temp_path / name
        pkg_dir.mkdir(exist_ok=True)

        # Create __init__.py
        init_file = pkg_dir / "__init__.py"
        init_file.write_text(f'"""Test package {name}."""\n__version__ = "1.0.0"\n')

        # Create a submodule
        module_file = pkg_dir / "module1.py"
        module_file.write_text(f'"""Module 1."""\ndef func1():\n    return "hello"\n')

        return pkg_dir

    def test_reload_package_by_name(self):
        """Test reloading a package by string name."""
        pkg_dir = self.create_test_package()

        # Add to Python path and import
        sys.path.insert(0, str(self.temp_path))

        try:
            # Import the package
            import test_reload_pkg

            # Mock the internal reload function
            with patch('ida_reloader.ida_reloader._reload_package_with_graph') as mock_reload:
                reload_package("test_reload_pkg")

                # Check that internal reload was called
                mock_reload.assert_called_once()
                args, kwargs = mock_reload.call_args
                self.assertEqual(kwargs['base_package'], "test_reload_pkg")
        finally:
            sys.path.remove(str(self.temp_path))

    def test_reload_package_by_module_object(self):
        """Test reloading a package by module object."""
        pkg_dir = self.create_test_package()

        sys.path.insert(0, str(self.temp_path))

        try:
            # Import the package
            import test_reload_pkg

            # Mock the internal reload function
            with patch('ida_reloader.ida_reloader._reload_package_with_graph') as mock_reload:
                reload_package(test_reload_pkg)

                # Check that internal reload was called
                mock_reload.assert_called_once()
                args, kwargs = mock_reload.call_args
                self.assertEqual(kwargs['base_package'], "test_reload_pkg")
        finally:
            sys.path.remove(str(self.temp_path))

    def test_reload_package_not_loaded(self):
        """Test reloading a package that is not loaded."""
        # Try to reload a package that doesn't exist in sys.modules
        with patch('builtins.print') as mock_print:
            reload_package("nonexistent_package")

            # Should print an error message
            mock_print.assert_called()
            call_args = str(mock_print.call_args)
            self.assertIn("not loaded", call_args.lower())

    def test_reload_package_with_skip(self):
        """Test reloading a package with skip prefixes."""
        pkg_dir = self.create_test_package()

        sys.path.insert(0, str(self.temp_path))

        try:
            # Import the package
            import test_reload_pkg

            # Mock the internal reload function
            with patch('ida_reloader.ida_reloader._reload_package_with_graph') as mock_reload:
                reload_package("test_reload_pkg", skip=["test_reload_pkg.vendor"])

                # Check that skip was passed correctly
                mock_reload.assert_called_once()
                args, kwargs = mock_reload.call_args
                self.assertEqual(kwargs.get('skip_prefixes'), ("test_reload_pkg.vendor",))
        finally:
            sys.path.remove(str(self.temp_path))

    def test_reload_package_with_suppress_errors(self):
        """Test reloading a package with error suppression."""
        pkg_dir = self.create_test_package()

        sys.path.insert(0, str(self.temp_path))

        try:
            # Import the package
            import test_reload_pkg

            # Mock the internal reload function
            with patch('ida_reloader.ida_reloader._reload_package_with_graph') as mock_reload:
                reload_package("test_reload_pkg", suppress_errors=True)

                # Check that suppress_errors was passed correctly
                mock_reload.assert_called_once()
                args, kwargs = mock_reload.call_args
                self.assertTrue(kwargs.get('suppress_errors'))
        finally:
            sys.path.remove(str(self.temp_path))

    def test_reload_single_module(self):
        """Test reloading a single module (not a package)."""
        # Create a single module file
        module_file = self.temp_path / "single_module.py"
        module_file.write_text('"""Single module."""\ndef func():\n    return 42\n')

        sys.path.insert(0, str(self.temp_path))

        try:
            # Import the module
            import single_module

            # Mock importlib.reload
            with patch('importlib.reload') as mock_reload:
                reload_package(single_module)

                # Should call importlib.reload directly
                mock_reload.assert_called_once_with(single_module)
        finally:
            sys.path.remove(str(self.temp_path))


if __name__ == '__main__':
    unittest.main()
