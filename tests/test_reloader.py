"""Unit tests for Reloader class."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Import from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from ida_reloader import Reloader


class TestReloader(unittest.TestCase):
    """Test cases for Reloader class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove test modules from sys.modules
        to_remove = [key for key in sys.modules.keys() if key.startswith('test_reloader_pkg')]
        for key in to_remove:
            del sys.modules[key]

        # Clean up temporary directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def create_test_package(self, name="test_reloader_pkg"):
        """Create a test package."""
        pkg_dir = self.temp_path / name
        pkg_dir.mkdir(exist_ok=True)

        # Create __init__.py
        init_file = pkg_dir / "__init__.py"
        init_file.write_text('"""Test package."""\n__version__ = "1.0.0"\n')

        return pkg_dir

    def test_reloader_init(self):
        """Test Reloader initialization."""
        reloader = Reloader(
            base_package="test_pkg",
            pkg_path=["/fake/path"],
            skip_prefixes=("test_pkg.vendor",),
            priority_prefixes=("test_pkg.core",),
            suppress_errors=True
        )

        self.assertEqual(reloader.base_pkg, "test_pkg")
        self.assertEqual(reloader.pkg_path, ["/fake/path"])
        self.assertEqual(reloader.skip, ("test_pkg.vendor",))
        self.assertEqual(reloader.priority, ("test_pkg.core",))
        self.assertTrue(reloader.suppress)

    def test_reloader_scan(self):
        """Test Reloader scan method."""
        pkg_dir = self.create_test_package()
        sys.path.insert(0, str(self.temp_path))

        try:
            import test_reloader_pkg

            reloader = Reloader(
                base_package="test_reloader_pkg",
                pkg_path=test_reloader_pkg.__path__
            )

            # Mock the scanner
            with patch.object(reloader._scanner, 'scan') as mock_scan:
                reloader.scan()

                # Check that scan was called
                mock_scan.assert_called_once()
                args, kwargs = mock_scan.call_args
                self.assertEqual(args[1], "test_reloader_pkg.")
        finally:
            sys.path.remove(str(self.temp_path))

    def test_reloader_reload_all(self):
        """Test Reloader reload_all method."""
        pkg_dir = self.create_test_package()
        sys.path.insert(0, str(self.temp_path))

        try:
            import test_reloader_pkg

            reloader = Reloader(
                base_package="test_reloader_pkg",
                pkg_path=test_reloader_pkg.__path__
            )

            # Mock scan and topo_order
            with patch.object(reloader._scanner, 'scan'):
                with patch.object(reloader._dg, 'topo_order', return_value=[]):
                    with patch.object(reloader._dg, 'get_cycles', return_value=[]):
                        reloader.reload_all()

                        # Should have called scan
                        reloader._scanner.scan.assert_called_once()
        finally:
            sys.path.remove(str(self.temp_path))

    def test_reloader_reload_all_with_priority(self):
        """Test Reloader reload_all with priority prefixes."""
        pkg_dir = self.create_test_package()
        sys.path.insert(0, str(self.temp_path))

        try:
            import test_reloader_pkg

            reloader = Reloader(
                base_package="test_reloader_pkg",
                pkg_path=test_reloader_pkg.__path__,
                priority_prefixes=("test_reloader_pkg.core",)
            )

            # Mock modules in sys.modules
            sys.modules["test_reloader_pkg.core.module"] = Mock()
            sys.modules["test_reloader_pkg.other.module"] = Mock()

            mock_order = [
                "test_reloader_pkg.other.module",
                "test_reloader_pkg.core.module"
            ]

            with patch.object(reloader._scanner, 'scan'):
                with patch.object(reloader._dg, 'topo_order', return_value=mock_order):
                    with patch.object(reloader._dg, 'get_cycles', return_value=[]):
                        with patch('importlib.reload') as mock_reload:
                            reloader.reload_all()

                            # Check that core module was reloaded first
                            calls = mock_reload.call_args_list
                            self.assertEqual(len(calls), 2)
                            # First call should be the core module
                            self.assertEqual(
                                calls[0][0][0],
                                sys.modules["test_reloader_pkg.core.module"]
                            )
        finally:
            sys.path.remove(str(self.temp_path))
            # Clean up mock modules
            sys.modules.pop("test_reloader_pkg.core.module", None)
            sys.modules.pop("test_reloader_pkg.other.module", None)

    def test_reloader_reload_all_with_skip(self):
        """Test Reloader reload_all with skip prefixes."""
        pkg_dir = self.create_test_package()
        sys.path.insert(0, str(self.temp_path))

        try:
            import test_reloader_pkg

            reloader = Reloader(
                base_package="test_reloader_pkg",
                pkg_path=test_reloader_pkg.__path__,
                skip_prefixes=("test_reloader_pkg.vendor",)
            )

            # Mock modules
            sys.modules["test_reloader_pkg.vendor.lib"] = Mock()
            sys.modules["test_reloader_pkg.core.module"] = Mock()

            with patch.object(reloader._scanner, 'scan'):
                with patch.object(reloader._dg, 'topo_order') as mock_topo:
                    with patch.object(reloader._dg, 'get_cycles', return_value=[]):
                        reloader.reload_all()

                        # Check that skip was passed to topo_order
                        mock_topo.assert_called_once()
                        args, kwargs = mock_topo.call_args
                        skip_set = kwargs['skip']
                        self.assertIn("test_reloader_pkg.vendor.lib", skip_set)
        finally:
            sys.path.remove(str(self.temp_path))
            sys.modules.pop("test_reloader_pkg.vendor.lib", None)
            sys.modules.pop("test_reloader_pkg.core.module", None)

    def test_reloader_plugin_context(self):
        """Test Reloader plugin_context context manager."""
        pkg_dir = self.create_test_package()
        sys.path.insert(0, str(self.temp_path))

        try:
            import test_reloader_pkg

            reloader = Reloader(
                base_package="test_reloader_pkg",
                pkg_path=test_reloader_pkg.__path__
            )

            # Mock plugin
            mock_plugin = Mock()
            mock_plugin.is_loaded.return_value = True

            with patch.object(reloader, 'reload_all'):
                with reloader.plugin_context(mock_plugin):
                    # Plugin should be unloaded
                    mock_plugin.unload.assert_called_once()

                # After context, reload_all should be called
                reloader.reload_all.assert_called_once()
                # And plugin should be loaded
                mock_plugin.load.assert_called_once()
        finally:
            sys.path.remove(str(self.temp_path))


if __name__ == '__main__':
    unittest.main()
