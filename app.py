import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd, check_price, validate_password

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

passwords_error_codes={\
-1:"Password should have at least 8 characters",\
-2:"Missing lower letter",\
-3:"Where is capital letter",\
-4:"Digit man ...",\
-5:"You're not special"
}

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    # compute total value
    # total =
    # loop over all shares and compute
    # for symbol in shares
    shares_dict=db.execute("SELECT t_symbol, t_shares FROM shares WHERE userid = ?", session["user_id"])
    shares_values=0
    for share in shares_dict:
        response=lookup(share["t_symbol"])
        share["t_price"]=response["price"]
        share["t_name"]=response["name"]
        share["t_total"]=share["t_price"] * share["t_shares"]
        shares_values=shares_values + share["t_shares"] * share["t_price"]
        # end of computation
        share["t_total"]=usd(share["t_total"])
        share["t_price"]=usd(share["t_price"])
    print(shares_dict)
    total=cash+shares_values
    return render_template("index.html", username=session["username"], cash = usd(cash), total=usd(total), shares=shares_dict)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("Empty symbol", 400)
        if not shares:
            return apology("Missing shares number", 400)
        if not shares.isnumeric():
            return apology("Number invalid", 400)
        if int(shares) < 1:
            return apology("Number invalid", 400)
        symbol = symbol.upper()
        response = lookup(symbol)
        if not response:
            return apology("Invalid symbol", 400)
        # check how much cash user has

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        if (response["price"] * int(shares) > cash):
            return apology("Get a better job man ...", 333)

        # subtract price from user's cash

        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - response["price"] * int(shares), session["user_id"])

        prev_shares = db.execute("SELECT t_shares FROM shares WHERE t_symbol = ? AND userid = ?", symbol, session["user_id"])
        if not prev_shares:
            db.execute("INSERT INTO shares ('userid', 't_symbol', 't_shares') VALUES(?,?,?)", session["user_id"], symbol, int(shares))
        else:
            db.execute("UPDATE shares SET t_shares = ? WHERE userid = ? AND t_symbol = ?", int(prev_shares[0]["t_shares"]) + int(shares), session["user_id"], symbol)
        # find how much shared does user has of particular compasymbolny
        current_time = datetime.now()
        current_date = f"{current_time.year}-{current_time.month:02d}-{current_time.day:02d} {current_time.hour:02d}:{current_time.minute:02d}:{current_time.second:02d}"
        db.execute("INSERT INTO history \
            ('userid', 't_symbol','t_shares','t_price', 't_type', 't_date') VALUES(?,?,?,?,?,?)", \
            session["user_id"], symbol, int(shares), response["price"], 'buy', current_date)

        # Printing attributes of now().
        print ("The attributes of now() are : ")

        print ("Year: ", end = "")
        print (current_time.year)

        print ("Month: ", end = "")
        print (current_time.month)

        print ("Day: ", end = "")
        print (current_time.day)
        print(current_time.hour)
        print(current_time.minute)
        print(current_time.second)
        return redirect("/")
    # GET method
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions=db.execute("SELECT * FROM history WHERE userid = ?", session["user_id"])
    for transaction in transactions:
        if transaction["t_type"] == "sell":
            transaction["t_shares"]=-transaction["t_shares"]
    print(transactions)
    return render_template("history.html", transactions=transactions)

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
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = username
        # Redirect user to home page
        return redirect("/")

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
            return apology("Empty symbol", 400)
        response = lookup(symbol)
        # symbol does not exist
        if not response:
            return apology("Invalid symbol", 400)
        else:
            return render_template("quoted.html", company=response["name"], symbol=response["symbol"], price=usd(response["price"]))
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
        password2 = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # check if username already exists
        elif len(db.execute("SELECT id FROM users WHERE username = ?", username)) > 0:
            return apology("username already exist", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure passwords match
        elif password != password2:
            return apology("passwords don't match", 400)

        # checking strength of password
        else:
            retval_password = validate_password(password)
            if (retval_password != 0):
                return apology(passwords_error_codes[retval_password], 400)

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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("Choose a symbol", 400)
        if not shares:
            return apology("Missing shares", 400)
        # validate if user posseses appriopriate amount of shares
        current_shares=int(db.execute("SELECT t_shares FROM shares WHERE userid = ? AND t_symbol = ?", session["user_id"], symbol)[0]["t_shares"])
        if (int(shares) > current_shares):
            return apology("Siała baba mak\nNi mosz tyle", 400)

        price = check_price(symbol)

        # add to cash value of shares
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + price * int(shares), session["user_id"])

        # update the database
        if (int(shares) == current_shares):
        # user sold all shares -- remove field
            db.execute("DELETE FROM shares WHERE userid = ? AND t_symbol = ?", session["user_id"], symbol)
        elif(int(shares) < current_shares):
            db.execute("UPDATE shares SET t_shares = ? WHERE userid = ? AND t_symbol = ?", current_shares - int(shares), session["user_id"], symbol)

        # update history
        current_time = datetime.now()
        current_date = f"{current_time.year}-{current_time.month:02d}-{current_time.day:02d} {current_time.hour:02d}:{current_time.minute:02d}:{current_time.second:02d}"
        db.execute("INSERT INTO history \
            ('userid', 't_symbol','t_shares','t_price', 't_type', 't_date') VALUES(?,?,?,?,?,?)", \
            session["user_id"], symbol, int(shares), price, 'sell', current_date)
        return redirect("/")
    else:
        symbols = db.execute("SELECT t_symbol FROM shares WHERE userid = ?", session["user_id"])
        return render_template("sell.html", symbols=symbols)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        userid = session["user_id"]
        # Ensure username was submitted
        if not old_password or not new_password:
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", userid)

        # Ensure username exists and password is correct
        if not check_password_hash(rows[0]["hash"], old_password):
            return apology("invalid password", 400)

        if old_password == new_password:
            return apology("New password is an old one :(", 400)

        retval_password = validate_password(new_password)
        if (retval_password != 0):
                return apology(passwords_error_codes[retval_password], 400)

        # change password in a database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), userid)
        # Redirect user to home page
        return redirect("/")
    # GET method
    else:
        return render_template("change_password.html")
