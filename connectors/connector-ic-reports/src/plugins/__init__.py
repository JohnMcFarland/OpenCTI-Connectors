"""
plugins/__init__.py
Plugin registry for CISA connector.
"""
from __future__ import annotations
import importlib
import logging
from base_plugin import BasePlugin

PLUGIN_MODULES = [
    "plugins.cisa",
]

def load_plugins(config: dict, log: logging.Logger) -> list[BasePlugin]:
    plugins = []
    plugin_configs = config.get("plugins", {})
    for module_name in PLUGIN_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            log.warning("Could not import plugin module '%s': %s", module_name, e)
            continue
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BasePlugin)
                and attr is not BasePlugin
                and hasattr(attr, "name")
                and attr.name is not NotImplemented
            ):
                plugin_key = attr.name.lower().replace(" ", "_")
                plugin_cfg = plugin_configs.get(plugin_key, {})
                if not plugin_cfg.get("enabled", True):
                    log.info("Plugin '%s' is disabled in config, skipping.", attr.name)
                    continue
                try:
                    instance = attr(config=plugin_cfg, logger=log)
                    plugins.append(instance)
                    log.info("Loaded plugin: %s", attr.name)
                except Exception as e:
                    log.error("Failed to instantiate plugin '%s': %s", attr.name, e)
    return plugins
