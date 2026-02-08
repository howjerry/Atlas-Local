def debug_output(value):
    print("Debug:", value)

def process_data(data):
    print(f"Processing {len(data)} items")
    return [x * 2 for x in data]
