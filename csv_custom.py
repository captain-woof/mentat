# HELPER
def sanitiseForCsv(text: str):
    # Check if the value needs to be quoted
    if any(char in text for char in ['"', ',', '\n', '\r']):
        # Escape double quotes by replacing them with two double quotes
        text = text.replace('"', '""')
        # Enclose the value in double quotes
        return f'"{text}"'
    return text