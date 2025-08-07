import re
import os

# A set of reserved filenames that are illegal on Windows.
# We will check against these in a case-insensitive manner.
RESERVED_FILENAMES = {
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
    "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

# Regex to find illegal characters in a filename.
# Includes:
# - Control characters (0-31)
# - Windows illegal characters: < > : " / \ | ? *
ILLEGAL_CHAR_REGEX = re.compile(r'[\x00-\x1f<>:"/\\|?*]')

def sanitizeFilename(filename: str, replacement: str = "_", max_length: int = 240) -> str:
    """
    Sanitizes a string to be a safe and valid filename.

    This function performs several steps to ensure security and cross-platform compatibility:
    1.  Handles None or empty input.
    2.  Separates the filename base from its extension.
    3.  Removes illegal characters and control characters.
    4.  Checks against Windows reserved filenames (e.g., "CON", "LPT1").
    5.  Prevents path traversal by removing path separators.
    6.  Removes leading/trailing whitespace and dots.
    7.  Ensures the filename is not empty after sanitization.
    8.  Truncates the filename to a safe maximum length.

    Args:
        filename: The input filename string to sanitize.
        replacement: The character to use for replacing illegal characters.
        max_length: The maximum allowed length for the final sanitized base name.

    Returns:
        A sanitized, safe-to-use filename string.
    """
    if not filename:
        return "unnamed_file"

    # 1. Separate the base name from the extension
    base_name, extension = os.path.splitext(filename)

    # 2. Sanitize the base name
    # Replace illegal characters with the replacement character
    sanitized_base = ILLEGAL_CHAR_REGEX.sub(replacement, base_name)
    
    # 3. Remove leading/trailing whitespace and dots
    # Windows automatically removes these, which can be confusing.
    sanitized_base = sanitized_base.strip(". ")

    # 4. Check against reserved filenames (case-insensitive)
    if sanitized_base.upper() in RESERVED_FILENAMES:
        sanitized_base = replacement + sanitized_base

    # 5. Ensure the base name is not empty after cleaning
    if not sanitized_base:
        sanitized_base = "unnamed_file"

    # 6. Truncate the sanitized base name to the max length
    sanitized_base = sanitized_base[:max_length]
    
    # 7. Re-attach the original extension
    # Extensions are generally safe but we remove path separators from them too.
    safe_extension = ILLEGAL_CHAR_REGEX.sub(replacement, extension)

    return sanitized_base + safe_extension
