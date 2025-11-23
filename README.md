# IDA Reloader

A hot-reload infrastructure for IDA plugins with dependency graph analysis and cycle detection.

Special thanks to [@w00tzenheimer](https://github.com/w00tzenheimer) [`d810-ng`](https://github.com/w00tzenheimer/d810-ng) project that showed this very elegant pattern.

## Features

- **Dependency graph analysis**: Automatically tracks module dependencies and reloads in correct order
- **Cycle detection**: Detects and reports circular import dependencies
- **Simple API**: Easy-to-use `reload_package()` function for basic hot-reloading
- **Advanced control**: `Reloader` class for priority-based reloading and custom workflows
- **Reloadable infrastructure**: The reloader itself can be reloaded without losing state

## Quick Start

### Simple Package Reloading

For basic hot-reloading of a package, use the `reload_package()` function:

```python
from ida_reloader import reload_package

# Reload by module object
import mypackage
reload_package(mypackage)

# Or by package name
reload_package("mypackage")

# Skip certain submodules
reload_package("mypackage", skip=["mypackage.vendor", "mypackage.legacy"])

# Suppress ModuleNotFoundError during reload
reload_package(mypackage, suppress_errors=True)
```

This function:
- Automatically scans all modules in the package
- Builds a dependency graph
- Detects import cycles
- Reloads modules in topological order (dependencies first)

### Advanced: IDA Plugin Integration

For IDA plugins with advanced reload requirements (priority modules, custom hooks):

```python
import ida_hexrays
import ida_kernwin
import idaapi

import ida_reloader


class _UIHooks(idaapi.UI_Hooks):

    def ready_to_run(self):
        pass


class ReloadablePlugin(ida_reloader.ReloadablePluginBase, idaapi.plugin_t, idaapi.action_handler_t):
    #
    # Plugin flags:
    # - PLUGIN_MOD: plugin may modify the database
    # - PLUGIN_PROC: Load/unload plugin when an IDB opens / closes
    # - PLUGIN_HIDE: Hide plugin from the IDA plugin menu  (if this is set, wanted_hotkey is ignored!)
    # - PLUGIN_FIX: Keep plugin alive after IDB is closed
    #
    #

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD
    wanted_name = "PLUGIN_NAME_HERE"
    wanted_hotkey = "Ctrl-Shift-Q"
    comment = "Interface to the PLUGIN_NAME_HERE plugin"
    help = ""

    def __init__(
        self,
        *,
        global_name: str,
        base_package_name: str,
        plugin_class: str,
    ):
        super().__init__(global_name, base_package_name, plugin_class, _UIHooks, idaapi.PLUGIN_SKIP, idaapi.PLUGIN_OK)
        self.suppress_reload_errors = False

    @override
    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        return idaapi.AST_ENABLE_ALWAYS

    @_compat.override
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        with self.plugin_setup_reload():
            self.reload()
        return 1

    def register_reload_action(self):
        idaapi.register_action(
            idaapi.action_desc_t(
                f"{self.global_name}:reload_plugin",
                f"Reload plugin: {self.global_name}",
                self,
            )
        )

    def unregister_reload_action(self):
        idaapi.unregister_action(f"{self.global_name}:reload_plugin")

    @override
    def init(self):
        if not init_hexrays():
            print(f"{self.wanted_name} need Hex-Rays decompiler. Skipping")
            return idaapi.PLUGIN_SKIP

        kv = ida_kernwin.get_kernel_version().split(".")
        if (int(kv[0]) < 7) or ((int(kv[0]) == 7) and (int(kv[1]) < 5)):
            print(f"{self.wanted_name} need IDA version >= 7.5. Skipping")
            return idaapi.PLUGIN_SKIP
        return super().init()

    @override
    def late_init(self):
        super().late_init()
        if not ida_hexrays.init_hexrays_plugin():
            print(f"{self.wanted_name} need Hex-Rays decompiler. Unloading...")
            self.term()
        print(f"{self.wanted_name} initialized (version {PLUGIN_VERSION})")

    @override
    def run(self, args):
        with self.plugin_setup_reload():
            self.reload()

    def reload(self):
        """Hot-reload the *entire* package with priority-based reloading.

        This method creates a fresh Reloader instance.

        The reloader:

        1. Scans all modules in the package and builds a dependency graph
        2. Detects strongly-connected components (import cycles)
        3. Produces a topological order respecting dependencies
        4. Reloads priority modules first (reloadable, then registry)
        5. Reloads remaining modules in dependency order

        """

        # Create a NEW Reloader instance to pick up any changes to the class
        reloader = ida_reloader.Reloader(
            base_package=self.base_package_name,
            pkg_path=PLUGIN.__path__,
            skip_prefixes=(f"{self.base_package_name}.registry",),
            priority_prefixes=(
                f"{self.base_package_name}.registry",    # Then registry (if not skipped)
            ),
            suppress_errors=self.suppress_reload_errors,
        )

        # Perform the reload
        reloader.reload_all()


def PLUGIN_ENTRY():
    return ReloadablePlugin()
```

## API Reference

### `reload_package(target, *, skip=(), suppress_errors=False)`

Recursively reload a package and its submodules in dependency order.

**Parameters:**
- `target` (str | types.ModuleType): The package name or module object to reload
- `skip` (Sequence[str]): Module name prefixes to exclude from reloading
- `suppress_errors` (bool): If True, ignore ModuleNotFoundError during reload

**Example:**
```python
from ida_reloader import reload_package
import mypackage

# Simple reload
reload_package(mypackage)

# With options
reload_package("mypackage", skip=["mypackage.vendor"], suppress_errors=True)
```

### `Reloader` Class

Advanced hot-reload manager with priority-based reload ordering.

**Constructor:**
```python
Reloader(
    base_package: str,
    pkg_path: Iterable[str],
    *,
    skip_prefixes: Sequence[str] = (),
    priority_prefixes: Sequence[str] = (),
    suppress_errors: bool = False
)
```

**Parameters:**
- `base_package`: Base package name (e.g., "mypackage")
- `pkg_path`: Package search paths (e.g., `mypackage.__path__`)
- `skip_prefixes`: Module prefixes to skip during reload
- `priority_prefixes`: Module prefixes to reload first (in order given)
- `suppress_errors`: Whether to suppress ModuleNotFoundError

**Methods:**
- `scan()`: Scan all modules and update dependency graph
- `reload_all()`: Reload all modules in dependency order with priority handling

**Example:**
```python
from ida_reloader import Reloader

reloader = Reloader(
    base_package="mypackage",
    pkg_path=mypackage.__path__,
    priority_prefixes=("mypackage.core",),
    skip_prefixes=("mypackage.vendor",)
)
reloader.reload_all()
```

## How It Works

1. **Module Scanning**: Recursively scans all modules in the package using `pkgutil.walk_packages()`

2. **Dependency Analysis**: Parses each module's AST to extract import statements and build a dependency graph
   - Handles relative imports (`. import foo`, `from .. import bar`)
   - Ignores imports inside `TYPE_CHECKING` guards
   - Tracks both forward and reverse dependencies

3. **Cycle Detection**: Uses Kosaraju's algorithm to find strongly-connected components (import cycles)
   - Reports detected cycles as warnings
   - Handles cycles gracefully during reload

4. **Topological Sort**: Produces a reload order that respects dependencies
   - Dependencies are reloaded before modules that import them
   - Priority modules are reloaded first (if using `Reloader` class)
   - Implicit parent package dependencies are added (`pkg.sub` depends on `pkg`)

5. **Hot Reload**: Reloads modules in the computed order using `importlib.reload()`

## Use Cases

- **IDA Plugin Development**: Reload your entire plugin without restarting IDA
- **Interactive Development**: Test code changes immediately in long-running processes
- **Debugging**: Quickly iterate on fixes without restarting your application
- **Dynamic Code Updates**: Update running systems without downtime

## Requirements

- Python 3.10+ (uses modern type annotations and match/case)
- For IDA plugins: IDA Pro 7.5+

## License

See LICENSE file for details.
