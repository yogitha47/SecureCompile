# ==========================================
# SecureCompile - Symbol Table
# ==========================================


class SymbolTable:
    """
    Stores information about variables declared
    in the source program.
    """

    def __init__(self):
        self.symbols = {}

    # --------------------------------------
    # Add a variable
    # --------------------------------------

    def declare(self, name, data_type, initialized=False):
        """
        Add a variable to the symbol table.

        Returns:
            True  -> declaration successful
            False -> variable already exists
        """

        if name in self.symbols:
            return False

        self.symbols[name] = {
            "type": data_type,
            "initialized": initialized
        }

        return True

    # --------------------------------------
    # Check whether variable exists
    # --------------------------------------

    def exists(self, name):
        return name in self.symbols

    # --------------------------------------
    # Get variable information
    # --------------------------------------

    def lookup(self, name):
        return self.symbols.get(name)

    # --------------------------------------
    # Mark variable as initialized
    # --------------------------------------

    def initialize(self, name):
        if name in self.symbols:
            self.symbols[name]["initialized"] = True

    # --------------------------------------
    # Check initialization status
    # --------------------------------------

    def is_initialized(self, name):
        if name not in self.symbols:
            return False

        return self.symbols[name]["initialized"]

    # --------------------------------------
    # Display symbol table
    # --------------------------------------

    def __repr__(self):
        return f"SymbolTable({self.symbols})"