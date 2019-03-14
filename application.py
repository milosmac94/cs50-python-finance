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

# Custom global variables
app.jinja_env.globals.update(usd=usd)
app.jinja_env.globals.update(lookup=lookup)
app.jinja_env.globals.update(round=round)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/", methods=["GET"])
@login_required
def index():
    """Show portfolio of stocks"""

    # From database, get stock name, symbol and sum of bought stocks grouped by stock name
    summary = db.execute("SELECT stock_name, stock_symbol, SUM(bought_shares) AS bought FROM tran_history where user = :user GROUP BY stock_name", user=session["username"])

    # Get current cash amount for logged in user
    cash = db.execute("SELECT cash FROM users where id = :id", id=session["user_id"])

    # Accumulator variable to hold sum of possesed stock values for logged in user
    total_value = 0

    # Calculate total stock in possesion
    for stock in summary:
        total_value += lookup(stock["stock_symbol"])["price"] * stock["bought"]

    return render_template("index.html", summary=summary, cash=cash, total_value=total_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        # Prevent entering of non-integer values for shares (str.isdigit() returns true only if all characters in string are positive integers)
        if not request.form.get("shares").isdigit():
            return apology("Number of shares must be a positive integer!", 400)

        # Get amount of cash logged in user possesses
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])

        # Lookup an API to get stock data
        quote = lookup(request.form.get("symbol"))

        # Prevent entering incorrect symbol
        if quote is None:
            return apology("Incorrect or non-existant symbol!", 400)

        # Calculate price of amount of shares user wants to buy
        want_to_buy = quote["price"] * int(request.form.get("shares"))

        # Prevent buying if there is not enough cash on current user account
        if cash[0]["cash"] < want_to_buy:
            return apology("Not enough cash!", 400)

        # In case shares are positive, execute this block
        else:

            # Lower cash balance for current user for price of bought shares
            db.execute("UPDATE users SET cash = :cash - :want_to_buy WHERE username = :user", cash=cash[0]["cash"], want_to_buy=want_to_buy, user=session["username"])

            # Enter transaction details into tran_history table
            db.execute("INSERT INTO tran_history (user, stock_name, stock_symbol, action, bought_shares, price) VALUES(:user, :stock_name, :stock_symbol, :action, :bought_shares, :price)",
                        user=session["username"], stock_name=quote["name"], stock_symbol=quote["symbol"], action="B", bought_shares=int(request.form.get("shares")), price=want_to_buy)

            # Redirect user to portfolio page
            return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    username = request.args.get("username")

    database = db.execute("SELECT username FROM users")

    # initialize a list to hold usernames from database
    users_list = []

    # extract usernames from 'database' list of dictionaries and put in list
    for pair in database:
        for k, v in pair.items():
            users_list.append(v)

    # verify username is longer than 0 characters and doesn't exist in users list
    if len(username) > 0 and username not in users_list:
        return jsonify(True)

    else:
        return jsonify(False)


@app.route("/dashboard", methods=["GET"])
@login_required
def dash():
    return render_template("dashboard.html")


@app.route("/dashboard/add", methods=["GET", "POST"])
@login_required
def add():
    """Add virtual cash to account"""

    if request.method == "POST":
        amount = request.form.get("amount")

        current_cash = db.execute("SELECT cash FROM users where username = :user", user=session["username"])

        db.execute("UPDATE users SET cash = :amount + :current_cash WHERE username = :user", amount=amount, user=session["username"], current_cash=current_cash[0]["cash"])

        flash("Cash successfully added!")

        return redirect("/")

    else:
        return render_template("dashboard.html")


@app.route("/dashboard/change", methods=["GET", "POST"])
@login_required
def change():
    """Allow user to change password:
        Enter current password
        Enter new password
        Confirm new password"""

    if request.method == "POST":
        old_password = db.execute("SELECT hash FROM users where username = :user", user=session["username"])

        # Verify fields are not empty
        if not request.form.get("old_password") or not request.form.get("new_password") or not request.form.get("confirm_password"):
            return apology("Some fields are empty!", 400)

        # Verify old password equals what is in database
        if not check_password_hash(old_password[0]["hash"], request.form.get("old_password")):
            return apology("Incorrect old password!", 400)

        # Verify new password and password confirmation match
        if request.form.get("new_password") != request.form.get("confirm_password"):
            return apology("Confirmation fields don't match!", 400)

        # Verify old password and new password don't match
        if check_password_hash(old_password[0]["hash"], request.form.get("new_password")):
            return apology("Old and new password can't be identical!", 400)

        # Create password hash
        hash = generate_password_hash(request.form.get("new_password"), method='pbkdf2:sha256', salt_length=8)

        db.execute("UPDATE users SET hash = :hash WHERE username = :user", hash=hash, user=session["username"])

        flash("Password changed!")

        return redirect("/")

    else:
        return render_template("dashboard.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    history = db.execute("SELECT * FROM tran_history WHERE user = :user", user=session["username"])

    return render_template("history.html", history=history)


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
        session["username"] = rows[0]["username"]

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

        # Look up current stock price via API (lookup function definition in helpers.py)
        quote = lookup(request.form.get("symbol"))

        # Validation (refer to lookup function in helpers.py)
        if quote is None:
            return apology("Incorrect or non-existant symbol!", 400)

        return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Missing username!", 400)

        # Ensure password was submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Missing password!", 400)

        # Ensure password and password confirmation field match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match!", 400)

        # Create password hash
        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        # Insert new user into database
        id = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                        username=request.form.get("username"), hash=hash)

        # Return apology if username already exists
        if not id:
            return apology("Username already exists!", 400)

        # Save logged in session
        session["user_id"] = id
        session["username"] = request.form.get("username")

        # Redirect to main page
        return redirect("/")

    # If request method is GET (user reached route via link or via redirect), open the register page
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # From database, get stock name, symbol and sum of bought stocks grouped by stock name. Putting here for proper scope (to avoid repetition)
    summary = db.execute("SELECT stock_name, stock_symbol, SUM(bought_shares) AS bought FROM tran_history where user = :user GROUP BY stock_name", user=session["username"])

    if request.method == "POST":

        # Prevent not entering number of shares
        if not request.form.get("shares"):
            return apology("You didn't input number of shares to sell!", 400)

        # Prevent entering of negative number of shares
        if int(request.form.get("shares")) < 0:
            return apology("Number of shares can't be negative!", 400)

        # Get amount of cash logged in user possesses
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])

        # Lookup an API to get stock data
        quote = lookup(request.form.get("symbol"))

        # Prevent entering incorrect symbol
        if quote is None:
            return apology("Incorrect or non-existant symbol!", 400)

        # # From database, get stock name, symbol and sum of bought stocks grouped by stock name
        # summary = db.execute("SELECT stock_name, stock_symbol, SUM(bought_shares) AS bought FROM tran_history where user = :user GROUP BY stock_name", user=session["username"])

        # Render an apology if user does not own any stock for submitted symbol
        for stock in summary:
            own = len(summary)
            if stock["stock_symbol"] != request.form.get("symbol"):
                own -= 1
            if not own:
                return apology("User does not own any shares of that stock!", 400)

        # Calculate price for amount of shares user wants to sell
        want_to_sell = quote["price"] * int(request.form.get("shares"))

        # Get current number of shares for selected stock and current user from database
        sum = db.execute("SELECT SUM(bought_shares) AS bought from tran_history WHERE user = :user and stock_symbol = :stock", user=session["username"], stock=request.form.get("symbol"))

        if int(request.form.get("shares")) > int(sum[0]["bought"]):
            return apology("You don't own enough stock!", 400)

        # Raise cash balance for current user for price of bought shares
        db.execute("UPDATE users SET cash = :cash + :want_to_sell WHERE username = :user", cash=cash[0]["cash"], want_to_sell=want_to_sell, user=session["username"])

        # Enter transaction details into tran_history table (action = S for 'sell' and bought_shares is negative, hence the minus in front)
        db.execute("INSERT INTO tran_history (user, stock_name, stock_symbol, action, bought_shares, price) VALUES(:user, :stock_name, :stock_symbol, :action, :bought_shares, :price)",
                    user=session["username"], stock_name=quote["name"], stock_symbol=quote["symbol"], action="S", bought_shares=-int(request.form.get("shares")), price=want_to_sell)

        # Redirect user to portfolio page
        return redirect("/")

    else:
        # # From database, get stock name, symbol and sum of bought stocks grouped by stock name
        # summary = db.execute("SELECT stock_name, stock_symbol, SUM(bought_shares) AS bought FROM tran_history where user = :user GROUP BY stock_name", user=session["username"])

        return render_template("sell.html", summary=summary)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
