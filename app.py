import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# TOKEN = pk_527ac91768d745cfbdb3bc38b821fbc1

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

def validate_password(password):
    if len(password) < 8:
        return False
    else:
        return True

def username_exist(username):
    return db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"] == 1

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return render_template("index.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("Empty symbol", 399)
        if not shares:
            return apology("Missing shares number", 399)
        response = lookup(symbol)
        # symbol does not exist
        if not response:
            return apology("Invalid symbol", 399)
        return redirect("/")
    # GET method
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = request.form.get("username")
        print(session)
        # Redirect user to home page
        # return redirect("/")
        return render_template("index.html", username=username)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Empty symbol", 399)
        response = lookup(symbol)
        # symbol does not exist
        if not response:
            return apology("Invalid symbol", 399)
        else:
            return render_template("quoted.html", company=response["name"], symbol=response["symbol"], price=response["price"])
    # GET method
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # validation of data

        username = request.form.get("username")
        password = request.form.get("password")
        password2 = request.form.get("password2")
        # type(db.execute("SELECT COUNT\(username\) FROM users WHERE username = \'?\'", username) == '1')

        #debug
        print(db.execute("SELECT id FROM users WHERE username = ?", "Piotr"))
        print(db.execute("SELECT id FROM users WHERE username = ?", "Piotr")[0]["id"])
        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # check if username already exists
        elif len(db.execute("SELECT id FROM users WHERE username = ?", username)) > 0:
            return apology("username already exist", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Ensure passwords match
        elif password != password2:
            return apology("passwords don't match", 403)
    
        # checking strength of password
        # elif not validate_password(password):
        #    return apology("password too weak", 403)
         
        # Successful registration
        # write credentials to the database (username + hash of a password)
        db.execute("INSERT INTO users (username,hash) VALUES(?,?)", username, generate_password_hash(password))
        return redirect("/login")
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")
