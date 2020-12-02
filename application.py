import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response
    

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    id = session["user_id"]
    userInfo = db.execute("SELECT id,cash,stock,shares from users JOIN Holdings on users.id = Holdings.user_id WHERE id = ?", id)

    if not userInfo:
        cash = usd(10000)
        return render_template("index.html", userInfo={}, stocksInfo={}, total=usd(10000), cash=cash)

    stocksInfo = {}
    total = userInfo[0]["cash"]
    cash = usd(total)
    userInfo[0]["cash"] = usd(userInfo[0]["cash"])
    for row in userInfo:
        stock = lookup(row["stock"])
        stocksInfo[row["stock"]] = [usd(stock["price"]), stock["name"], usd(stock["price"] * row["shares"])]
        total += stock["price"] * row["shares"]
    total = usd(total)
    return render_template("index.html", userInfo=userInfo, stocksInfo=stocksInfo, total=total, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if shares < 0:
            return apology("please insert a positive integer")
        info = lookup(symbol)
        if not info:
            return apology("Can't find stock symbol")
        id = session["user_id"]
        rows = db.execute("SELECT * FROM users WHERE id = ?", id)
        if rows[0]["cash"] < (int(info["price"]) * shares):
            return apology("You don't have enough cash")
        holdings = db.execute("SELECT * FROM Holdings WHERE user_id = ?", id)
        if not holdings:
            db.execute("INSERT INTO Holdings (user_id, stock, shares) VALUES (?, ?, ?)", rows[0]["id"], symbol, shares)
        else:
            newShares = int(holdings[0]["shares"]) + shares
            db.execute("UPDATE Holdings SET shares = ? WHERE user_id = ?", newShares, id)
        db.execute("INSERT INTO History (user_id, stock, shares, price) VALUES (?, ?, ?, ?)",
                   rows[0]["id"], symbol, shares, info["price"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (rows[0]["cash"] - shares * info["price"]), id)
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    id = session["user_id"]
    userHistory = db.execute("SELECT * from history WHERE user_id = ? ORDER BY time DESC", id)
    for transaction in userHistory:
        transaction["price"] = usd(transaction["price"])
    return render_template("history.html", userHistory=userHistory)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        info = lookup(symbol)
        if not info:
            return apology("Can't find stock symbol")
        return render_template("quoted.html", name=info["name"], symbol=info["symbol"], price=usd(info["price"]))

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        password = request.form.get("password")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)
        elif not len(password) >= 8:
            return apology("password must be at least 8 characters long", 403)
        elif not (password == request.form.get("confirmation")):
            return apology("Passwords don't match")

        # Make sure username doesn't exist
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        if len(rows) != 0:
            return apology("Username already exists")

        # Add to database
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        # Redirect user to home page
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares")) * - 1
        if shares > 0:
            return apology("please insert a positive integer")
        info = lookup(symbol)
        if not info:
            return apology("Can't find stock symbol")
        id = session["user_id"]
        holdings = db.execute("SELECT shares FROM Holdings WHERE user_id = ? AND stock = ?", id, symbol)
        if holdings[0]["shares"] < (shares * -1) or not holdings[0]["shares"]:
            return apology("You don't have enough shares")
        cash = db.execute("SELECT cash FROM users WHERE id = ?", id)
        newShares = int(holdings[0]["shares"]) + shares
        db.execute("UPDATE Holdings SET shares = ? WHERE user_id = ?", newShares, id)
        db.execute("INSERT INTO History (user_id, stock, shares, price) VALUES (?, ?, ?, ?)", id, symbol, shares, info["price"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (cash[0]["cash"] - (shares * info["price"])), id)
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("sell.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
