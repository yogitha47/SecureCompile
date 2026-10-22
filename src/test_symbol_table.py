from symbol_table import SymbolTable


# Create a symbol table
table = SymbolTable()


# Declare variables
table.declare("x", "int", initialized=True)
table.declare("y", "int", initialized=False)


# Display the symbol table
print("\nSecureCompile Symbol Table:\n")
print(table)


# Check variables
print("\nVariable checks:\n")

print("x exists:", table.exists("x"))
print("y exists:", table.exists("y"))
print("z exists:", table.exists("z"))

print("\nx initialized:", table.is_initialized("x"))
print("y initialized:", table.is_initialized("y"))


# Initialize y
table.initialize("y")

print("\nAfter initializing y:")
print("y initialized:", table.is_initialized("y"))