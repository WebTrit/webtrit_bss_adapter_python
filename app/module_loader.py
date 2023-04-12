import logging
import importlib
import sys

class ModuleLoader:
    @classmethod
    def load_module_and_class(cls,
                                module_path: str,
                                module_name: str,
                                class_name: str,
                                root_package,
                                **kwargs):
        """Load a module from a given path and return a reference to a class,
        which can be used then to instantiate an object."""
        if module_path and module_path not in sys.path:
            # allow to include modules from a directory, other than
            # python's default location and the directory where main.py resides
            sys.path.append(module_path)

        if module_name in sys.modules:
            logging.debug(f"Module {module_name} is already loaded")
        else:
            try:
                module = importlib.import_module(module_name, package=root_package)
            except ImportError as e:
                logging.error(f"Error importing module '{module_name}': {e}")
                raise
            logging.info(f"Loaded module: {module_name}")

        try:
            class_ref = getattr(module, class_name)
        except AttributeError as e:
            logging.error(
                f"Error finding class '{class_name}' in module '{module_name}': {e}"
            )
            raise
        return class_ref
