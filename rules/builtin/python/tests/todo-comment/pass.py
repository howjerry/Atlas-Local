# This function validates user input
def validate_input(data):
    return isinstance(data, str) and len(data) > 0

# Helper for database operations
def get_connection(host, port):
    return {"host": host, "port": port}

# Calculate the total price including tax
def calculate_total(price, tax_rate):
    return price * (1 + tax_rate)
