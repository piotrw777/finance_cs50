import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""
    # Contact API
    try:
        api_key = os.environ.get("API_KEY")
        url = f"https://cloud.iexapis.com/stable/stock/{urllib.parse.quote_plus(symbol)}/quote?token={api_key}"
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException:
        return None

    # Parse response
    try:
        quote = response.json()
        return {
            "name": quote["companyName"],
            "price": float(quote["latestPrice"]),
            "symbol": quote["symbol"]
        }
    except (KeyError, TypeError, ValueError):
        return None


def check_price(symbol):
    response = lookup(symbol)
    return response["price"]


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"


def has_digit(str):
    digits={'0','1','2','3','4','5','6','7','8','9'}
    for char in str:
        if char in digits:
            return True
    return False


def has_upper_letter(str):
    for char in str:
        if char.isupper():
            return True
    return False


def has_lower_letter(str):
    for char in str:
        if char.islower():
            return True
    return False


def has_special_symbol(str):
    specials={'!','@','#','$','%','^','&','*','(', \
')','-','_','+','=',';',':','\"','\'',',','.','/',\
'<','>','?','[',']','|','\\','`'}
    for char in str:
        if char in specials:
            return True
    return False

# validation of password
# error codes:
# -1 - length < 8
# -2 - missing lower letter
# -3 - missing upper letter
# -4 - missing digit
# -5 - missing special character
def validate_password(password):
    if len(password) < 8:
        return -1
    if not has_lower_letter(password):
        return -2
    if not has_upper_letter(password):
        return -3
    if not has_digit(password):
        return -4
    if not has_special_symbol(password):
        return -5
    return 0


