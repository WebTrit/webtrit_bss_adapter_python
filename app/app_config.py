"""Supply the application with config values, that can
be overridden via env variables. 

Usage example:
        # using text config file
        import yaml
        from app_config import AppConfig

        config_file = 'my-config.yaml'
        with open(config_file, "r") as f:
            # Load the YAML content
            config = AppConfig(yaml.safe_load(f))
            host = config.get_conf_val('Server', 'IP', default = "127.0.0.1")

        # alternative, using only env variables
        from app_config import AppConfig
        config = AppConfig()
        host = config.get_conf_val('Server', 'IP', default = "127.0.0.1")       
"""
import os


class AppConfig(dict):
    def __setitem__(self, key, value):
        super().__setitem__(key.upper(), value)

    def get_case_insensitive(self, d: dict, key: str, default=None):
        """Return a value of dict key with case-insensetive match.
        the dictionary has to be passed as an extra argument, so it will
        work on nested dicts, which are not AppConfig."""
        if key in d:
            return d[key]  # easy-peasy
        # what is there is a key 'ABc' when we were requested 'AbC'?
        key_upper = key.upper()
        for x in d.keys():
            if x.upper() == key_upper:
                return d[x]
        # no luck
        return default

    def get_conf_val(self, *path, default=None):
        """Return a value of conf. parameter (defined by its path,
        which can be just a single string (e.g. "Server_Name"),
        "Section" and "Name" (for config files in [Section]Attr=Val
        format) or a path (e.g. "DB", "Cassandra", "foo", "bar")
        for deeply nested configs.

        The path elements are case INSENSITIVE, so "DB", "Cassandra", "foo", "bar"
        is equivalent to "DB", "CASSANDARA", "Foo", "Bar" and will work even
        if the actual config file params were defined as "db", "cassandra", "FOO", "BAR"

        The value is taken first from an environment
        variable or from the data in the config object (dict). The name of the
        env variable is produced as a combination of all path elements
        (converted to uppercase and joined via _). If an APP_NAME environment
        variable is defined, then the final name for the variable is prefixed
        with the <APP_NAME>_. For instance is APP_NAME equals to "abc", and
        the path is given as 'foo', 'bar, 'xyz' - then it will attempt to use
        a ABC_FOO_BAR_XYZ env variable.

        :param *path: Path to the config option e.g. 'Perl', 'Script'
        :param default: Default value (if does not exist in the config)
        :return: Parameter value
        """
        prefix = os.environ.get("APP_NAME", None)
        var_name = prefix

        val = self
        for x in path:
            if val is None or not isinstance(val, dict):
                # no such element
                val = None
                break
            val = self.get_case_insensitive(val, x, None )

        var_name = "_".join(path).upper()
        override_val = os.environ.get(var_name, None)
        if override_val is not None:
            val = override_val
        final_val = default if val is None else val

        return final_val

    def get_opt(self, section: str, param: str, default=None):
        """Same as get_conf_val but for 2-level configs (section + param name)"""
        return self.get_conf_val(section, param, default=default)
    
    def get_config_branch(self, *path):
        """Return a sub-branch of the config tree, starting from the given path.
        The path elements are case INSENSITIVE, so "DB", "Cassandra", "foo", "bar"
        is equivalent to "DB", "CASSANDARA", "Foo", "Bar" and will work even
        if the actual config file params were defined as "db", "cassandra", "FOO", "BAR"
        """
        val = self
        for x in path:
            if val is None or not isinstance(val, dict):
                # no such element
                val = None
                break
            val = self.get_case_insensitive(val, x, None )
        return AppConfig(val) if val is not None else None
    
    def get_mandatory_conf_val(self, *path):
        """Same as get_conf_val but raises an exception if the value is not found"""
        val = self.get_conf_val(*path)
        if val is None:
            raise Exception(f"Config value {path} is not defined")
        return val
