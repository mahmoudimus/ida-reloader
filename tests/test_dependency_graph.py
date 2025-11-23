"""Unit tests for DependencyGraph class."""
import ast
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ida_reloader import DependencyGraph


class TestDependencyGraph(unittest.TestCase):
    """Test cases for DependencyGraph class."""

    def setUp(self):
        """Set up test fixtures."""
        self.dg = DependencyGraph("test_pkg.")

    def test_init(self):
        """Test DependencyGraph initialization."""
        self.assertEqual(self.dg._pkg_prefix, "test_pkg.")
        self.assertEqual(self.dg._module_dependencies, {})
        self.assertEqual(self.dg._reverse_dependencies, {})
        self.assertTrue(self.dg._dirty)

    def test_process_import_node(self):
        """Test processing regular import statements."""
        dependencies = set()

        # Test importing a module with the package prefix
        code = "import test_pkg.module1"
        tree = ast.parse(code)
        import_node = tree.body[0]

        self.dg._process_import_node(import_node, dependencies)
        self.assertIn("test_pkg.module1", dependencies)

    def test_process_import_node_non_package(self):
        """Test that non-package imports are ignored."""
        dependencies = set()

        # Test importing a module without the package prefix
        code = "import os"
        tree = ast.parse(code)
        import_node = tree.body[0]

        self.dg._process_import_node(import_node, dependencies)
        self.assertNotIn("os", dependencies)

    def test_scan_dependencies_with_simple_imports(self):
        """Test scanning a file with simple imports."""
        # Create a temporary Python file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import test_pkg.module1\n")
            f.write("import test_pkg.module2\n")
            f.write("import os\n")
            temp_file = Path(f.name)

        try:
            deps = self.dg.scan_dependencies(temp_file)
            self.assertIn("test_pkg.module1", deps)
            self.assertIn("test_pkg.module2", deps)
            self.assertNotIn("os", deps)
        finally:
            temp_file.unlink()

    def test_scan_dependencies_with_from_imports(self):
        """Test scanning a file with from...import statements."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("from test_pkg.module1 import func1\n")
            f.write("from test_pkg.subpkg import module2\n")
            temp_file = Path(f.name)

        try:
            deps = self.dg.scan_dependencies(temp_file)
            self.assertIn("test_pkg.module1", deps)
            self.assertIn("test_pkg.subpkg", deps)
        finally:
            temp_file.unlink()

    def test_scan_dependencies_ignores_type_checking(self):
        """Test that imports inside TYPE_CHECKING blocks are ignored."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("from typing import TYPE_CHECKING\n")
            f.write("if TYPE_CHECKING:\n")
            f.write("    import test_pkg.module1\n")
            f.write("import test_pkg.module2\n")
            temp_file = Path(f.name)

        try:
            deps = self.dg.scan_dependencies(temp_file)
            self.assertNotIn("test_pkg.module1", deps)
            self.assertIn("test_pkg.module2", deps)
        finally:
            temp_file.unlink()

    def test_scan_dependencies_nonexistent_file(self):
        """Test scanning a nonexistent file."""
        deps = self.dg.scan_dependencies(Path("/nonexistent/file.py"))
        self.assertEqual(deps, set())

    def test_scan_dependencies_non_python_file(self):
        """Test scanning a non-Python file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Not Python code\n")
            temp_file = Path(f.name)

        try:
            deps = self.dg.scan_dependencies(temp_file)
            self.assertEqual(deps, set())
        finally:
            temp_file.unlink()

    def test_update_dependencies(self):
        """Test updating dependency tracking for a module."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import test_pkg.module1\n")
            f.write("import test_pkg.module2\n")
            temp_file = Path(f.name)

        try:
            self.dg.update_dependencies(temp_file, "test_pkg.main")

            # Check forward dependencies
            deps = self.dg.get_module_dependencies("test_pkg.main")
            self.assertIn("test_pkg.module1", deps)
            self.assertIn("test_pkg.module2", deps)

            # Check reverse dependencies
            rev_deps = self.dg.get_dependents("test_pkg.module1")
            self.assertIn("test_pkg.main", rev_deps)
        finally:
            temp_file.unlink()

    def test_get_transitive_dependents(self):
        """Test getting transitive dependents."""
        # Create a dependency chain where:
        # - A has no dependencies (base)
        # - B depends on A
        # - C depends on B
        # So B and C are transitive dependents of A
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("")  # A has no dependencies
            temp_file_a = Path(f.name)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import test_pkg.a\n")  # B depends on A
            temp_file_b = Path(f.name)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import test_pkg.b\n")  # C depends on B
            temp_file_c = Path(f.name)

        try:
            self.dg.update_dependencies(temp_file_a, "test_pkg.a")
            self.dg.update_dependencies(temp_file_b, "test_pkg.b")
            self.dg.update_dependencies(temp_file_c, "test_pkg.c")

            # A should have transitive dependents B and C
            trans_deps = self.dg.get_transitive_dependents("test_pkg.a")
            self.assertIn("test_pkg.b", trans_deps)
            self.assertIn("test_pkg.c", trans_deps)
        finally:
            temp_file_a.unlink()
            temp_file_b.unlink()
            temp_file_c.unlink()

    def test_topo_order_simple(self):
        """Test topological ordering with simple dependencies."""
        # Create dependencies: B depends on A
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import test_pkg.a\n")
            temp_file_b = Path(f.name)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("")
            temp_file_a = Path(f.name)

        try:
            self.dg.update_dependencies(temp_file_a, "test_pkg.a")
            self.dg.update_dependencies(temp_file_b, "test_pkg.b")

            order = self.dg.topo_order()
            # A should come before B
            self.assertLess(order.index("test_pkg.a"), order.index("test_pkg.b"))
        finally:
            temp_file_a.unlink()
            temp_file_b.unlink()

    def test_topo_order_with_skip(self):
        """Test topological ordering with skipped modules."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("")
            temp_file_a = Path(f.name)

        try:
            self.dg.update_dependencies(temp_file_a, "test_pkg.a")

            order = self.dg.topo_order(skip={"test_pkg.a"})
            self.assertNotIn("test_pkg.a", order)
        finally:
            temp_file_a.unlink()

    def test_get_cycles_simple(self):
        """Test cycle detection with simple circular dependency."""
        # Create a cycle: A -> B -> A
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import test_pkg.b\n")
            temp_file_a = Path(f.name)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import test_pkg.a\n")
            temp_file_b = Path(f.name)

        try:
            self.dg.update_dependencies(temp_file_a, "test_pkg.a")
            self.dg.update_dependencies(temp_file_b, "test_pkg.b")

            cycles = self.dg.get_cycles()
            # Should detect the cycle
            self.assertGreater(len(cycles), 0)
            # Find the cycle containing both a and b
            found_cycle = False
            for cycle in cycles:
                if "test_pkg.a" in cycle and "test_pkg.b" in cycle:
                    found_cycle = True
                    break
            self.assertTrue(found_cycle)
        finally:
            temp_file_a.unlink()
            temp_file_b.unlink()

    def test_get_stats(self):
        """Test getting dependency graph statistics."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import test_pkg.b\n")
            temp_file = Path(f.name)

        try:
            self.dg.update_dependencies(temp_file, "test_pkg.a")

            stats = self.dg.get_stats()
            self.assertEqual(stats["total_modules"], 1)
            self.assertIn("total_reverse_deps", stats)
        finally:
            temp_file.unlink()


if __name__ == '__main__':
    unittest.main()
