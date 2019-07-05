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
    #stocks combines transactions into all unique stocks
    #framework: {symbol:name,shares,price,total}
    stocks = {}
    #trs is a list of all transactions
    trs = db.execute("SELECT * FROM 'stocks' WHERE user_id = :id;",id=session["user_id"])
    for tr in trs:
        try:
            stocks[tr["symbol"]][1] += tr["shares"]
            stocks[tr["symbol"]][3] += lookup(tr["symbol"])["price"] * float(tr["shares"])
        except:
            stocks[tr["symbol"]] = []
            stocks[tr["symbol"]].append(lookup(tr["symbol"])["name"])
            stocks[tr["symbol"]].append(tr["shares"])
            stocks[tr["symbol"]].append(lookup(tr["symbol"])["price"])
            stocks[tr["symbol"]].append(lookup(tr["symbol"])["price"] * float(tr["shares"]))
    #https://stackoverflow.com/questions/5384914/how-to-delete-items-from-a-dictionary-while-iterating-over-it
    stocks = {sym:val for sym,val in stocks.items() if val[1]!=0}
    #see how much cash the current user has
    cash = db.execute("SELECT cash FROM 'users' WHERE id = :id;",id=session["user_id"])[0]["cash"]
    #add the cash the user has to his/her cash in stocks, to find the total
    total = 0
    for stock in stocks.values():
        total+=stock[3]
        stock[2] = usd(stock[2])
        stock[3] = usd(stock[3])
    total += cash
    return render_template("index.html", stocks=stocks, total=usd(total), cash=usd(cash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        #make sure the user inputs a valid symbol or number of shares
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol or lookup(symbol)==None:
            return apology("Please enter a valid symbol.")
        if not shares:
            return apology("Please enter a number of shares.")
        cash = db.execute("SELECT cash FROM 'users' WHERE id = :id;",id=session["user_id"])[0]["cash"]
        cost = lookup(symbol)["price"]*float(shares)
        #make sure the user isn't spending money he/she doesn't have
        if cost > cash:
            return apology("Insufficient funds.")
        #update data after purchase
        db.execute("INSERT INTO 'stocks' (user_id, symbol, shares) VALUES(:user_id, :symbol, :shares);",user_id=session["user_id"],symbol=symbol.upper(),shares=shares)
        db.execute("UPDATE 'users' SET 'cash'=:new_cash WHERE id=:id;",new_cash=cash-cost,id=session["user_id"])
        return redirect("/")
    else:
        return render_template("buy.html")


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
        rows = db.execute("SELECT * FROM users WHERE username = :username;", username=request.form.get("username"))

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
    if request.method == "POST":
        #make sure the user gives a valid symbol
        symbol = request.form.get("symbol")
        if not symbol or lookup(symbol)==None:
            return apology("Please enter a valid symbol.")
        else:
            data = lookup(symbol)
            price = usd(data["price"])
            return render_template("quoted.html", data=data, price=price)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET","POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        #make sure the user inputs a username
        if not username:
            return apology("No username was entered.")
        usernames= db.execute("SELECT username FROM 'users';")
        #make sure the username is not already taken
        for u in usernames:
            if u['username'] == username:
                return apology("This username is taken.")
        #make sure the password and the confirmation are inputted and match
        if not password or not request.form.get("confirmation"):
            return apology("No password was entered.")
        if password != request.form.get("confirmation"):
            return apology("The passwords do not match.")
        #update data with new user
        db.execute("INSERT INTO 'users' (username,hash) VALUES(:username, :password);", username=username, password=generate_password_hash(password))
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stocks = {}
    #stocks combines transactions into all unique stocks
    #framework: {symbol:name,shares,price}
    #trs is a list of all transactions
    trs = db.execute("SELECT * FROM 'stocks' WHERE user_id = :id;",id=session["user_id"])
    for tr in trs:
        try:
            stocks[tr["symbol"]][1] += tr["shares"]
        except:
            stocks[tr["symbol"]] = []
            stocks[tr["symbol"]].append(lookup(tr["symbol"])["name"])
            stocks[tr["symbol"]].append(tr["shares"])
            stocks[tr["symbol"]].append(lookup(tr["symbol"])["price"])
    if request.method == "POST":
        #make sure the user enters a valid symbol and a number of shares
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol or lookup(symbol) == None:
            return apology("Please enter a valid symbol.")
        if not shares:
            return apology("Please enter a number of shares.")
        max_shares = stocks[symbol][1]
        #make sure the user can't sell shares he/she doesn't have
        if max_shares < int(shares):
            return apology(f"You do not have that many shares of {stocks[symbol][0]}")
        #update data with sale
        cash = db.execute("SELECT cash FROM 'users' WHERE id = :id;",id=session["user_id"])[0]["cash"]
        sale = stocks[symbol][2]*float(shares)
        db.execute("INSERT INTO 'stocks' (user_id, symbol, shares) VALUES(:user_id, :symbol, :shares);",user_id=session["user_id"],symbol=symbol.upper(),shares='-'+shares)
        db.execute("UPDATE 'users' SET 'cash'=:new_cash WHERE id=:id;",new_cash=cash+sale,id=session["user_id"])
        return redirect("/")
    else:
        return render_template("sell.html",stocks=stocks)

@app.route("/add_cash", methods=["GET"])
@login_required
def add_cash():
    #it's not actually supposed to add cash (bamboozle the user)
    return render_template("add_cash.html")

@app.route("/change_pass", methods=["GET","POST"])
@login_required
def change_pass():
    if request.method == "POST":
        old_pass = db.execute("SELECT hash FROM 'users' WHERE id = :id;",id=session["user_id"])[0]["hash"]
        new_pass = request.form.get("new_pass")
        #make sure the user enters his/her old password correctly
        if not check_password_hash(old_pass,request.form.get("old_pass")):
            return apology("You did not enter your password correctly.")
        #make sure the user enters a new password
        if not new_pass:
            return apology("Please enter a new password.")
        #update data with new password
        db.execute("UPDATE 'users' SET 'hash'=:new_pass WHERE id=:id;",new_pass=generate_password_hash(new_pass),id=session["user_id"])
        return redirect("/")
    else:
        return render_template("change_pass.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
