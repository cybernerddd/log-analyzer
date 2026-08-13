from datetime import datetime, date
import urllib.parse

def decode_url(value):
    """
    input: str,
    Returns the human readable
    form of a percent encoding
    """
    return urllib.parse.unquote(value)

