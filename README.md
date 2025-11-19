# IDA Reloader

Special thanks to [@w00tzenheimer](https://github.com/w00tzenheimer) [`d810-ng`](https://github.com/w00tzenheimer/d810-ng) project that showed this very elegant pattern.

## How to use

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
