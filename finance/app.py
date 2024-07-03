import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    user_id = session["user_id"]
    print(f"User ID: {user_id}")

    # Query for user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    print(f"User Cash: {cash}")

    # Query for user's stocks
    rows = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", user_id)
    print(f"User Stocks: {rows}")

    # Get current prices for each stock
    portfolio = []
    total_value = cash
    for row in rows:
        quote = lookup(row["symbol"])
        if quote:
            total = quote["price"] * row["total_shares"]
            portfolio.append({
                "symbol": row["symbol"],
                "shares": row["total_shares"],
                "price": quote["price"],
                "total": total
            })
            total_value += total

    return render_template("index.html", portfolio=portfolio, cash=cash, total_value=total_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        print(f"Buy Request - Symbol: {symbol}, Shares: {shares}")

        if not symbol:
            return apology("must provide stock symbol", 400)

        quote = lookup(symbol)
        print(f"Quote: {quote}")

        if quote is None:
            return apology("invalid stock symbol", 400)

        try:
            shares = int(shares)
            if shares <= 0:
                return apology("must provide positive number of shares", 400)
        except ValueError:
            return apology("must provide valid number of shares", 400)

        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        total_cost = shares * quote["price"]
        print(f"Total Cost: {total_cost}, User Cash: {cash}")

        if cash < total_cost:
            return apology("can't afford", 400)

        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, user_id)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   user_id, symbol, shares, quote["price"])

        flash("Bought!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT symbol, shares, price, transacted FROM transactions WHERE user_id = ? ORDER BY transacted DESC", user_id)
    print(f"Transactions: {transactions}")
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        print(f"Login Attempt - Rows: {rows}")

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        print(f"Register Attempt - Username: {username}")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        elif not confirmation:
            return apology("must provide confirmation", 400)

        # Ensure passwords match
        elif password != confirmation:
            return apology("passwords do not match", 400)

        # Hash password
        hash = generate_password_hash(password)

        # Insert user into database
        try:
            new_user_id = db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash
            )
            print(f"New User ID: {new_user_id}")
        except ValueError:
            return apology("username already exists", 400)

        # Remember which user has logged in
        session["user_id"] = new_user_id

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        print(f"Quote Request - Symbol: {symbol}")

        if not symbol:
            return apology("must provide stock symbol", 400)

        quote = lookup(symbol)
        print(f"Quote: {quote}")

        if quote is None:
            return apology("invalid stock symbol", 400)

        return render_template("quoted.html", symbol=quote["symbol"], price=quote["price"])
    else:
        return render_template("quote.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        print(f"Sell Request - Symbol: {symbol}, Shares: {shares}")

        if not symbol:
            return apology("must provide stock symbol", 400)

        if not shares:
            return apology("must provide number of shares", 400)

        try:
            shares = int(shares)
            if shares <= 0:
                return apology("must provide positive number of shares", 400)
        except ValueError:
            return apology("must provide valid number of shares", 400)

        user_shares = db.execute("SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)
        if len(user_shares) != 1 or user_shares[0]["total_shares"] < shares:
            return apology("not enough shares", 400)

        quote = lookup(symbol)
        if quote is None:
            return apology("invalid stock symbol", 400)

        total_sale = shares * quote["price"]

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_sale, user_id)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   user_id, symbol, -shares, quote["price"])

        flash("Sold!")
        return redirect("/")
    else:
        stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", user_id)
        return render_template("sell.html", stocks=stocks)

if __name__ == "__main__":
    app.run(debug=True)
