from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from passlib.apps import custom_app_context as pwd_context
from tempfile import mkdtemp
from functools import wraps
import sqlite3

app = Flask(__name__)

if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

conn = sqlite3.connect('msgcast.db')
db = conn.cursor()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
@login_required
def index():

    db.execute("SELECT role FROM users WHERE username=?", (session["user_id"],))
    rolex = db.fetchall()

    db.execute("SELECT grp FROM users WHERE username=?", (session["user_id"],))
    grp = db.fetchall()

    db.execute("SELECT msgs.username, first_name||' '||last_name AS name, role, msg, time FROM msgs,users WHERE msgs.username = users.username AND grp=? ORDER BY time DESC",(grp[0][0],))
    msgs = db.fetchall()

    logged = session["user_id"]

    return render_template("index.html", **locals())

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # query database for username
        db.execute("SELECT * FROM users WHERE username = ?",(request.form.get("username"),))
        rows = db.fetchall()
        # db.close()

        # ensure username exists and password is correct
        if len(rows) != 1 or not pwd_context.verify(request.form.get("password"), rows[0][3]):
            flash("Invalid username and/or password")
            return render_template("login.html")

        # remember which user has logged in
        session["user_id"] = rows[0][0]

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out."""

    # forget any user_id
    session.clear()

    # redirect user to login form
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """signup user."""
     # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # query database for username
        db.execute("SELECT * FROM users WHERE username = ?",(request.form.get("regusername"),))
        rows = db.fetchall()

        # ensure username doesn't exist
        if len(rows) != 0:
            flash("This Username is already taken!")
            return render_template("signup.html")
       
        # check password match
        if request.form.get("reppassword") != request.form.get("regpassword"):
            flash("Passwords don't match")
            return render_template("signup.html")
        
        # password encryption
        hash = pwd_context.encrypt(request.form.get("regpassword"))
        
        #add user
        db.execute("INSERT INTO users(username, first_name, last_name, hash, grp, doj) VALUES(?, ?, ?, ?, ?, DATETIME(current_timestamp, '+05 hours','+30 minutes'))",(request.form.get("regusername"), request.form.get("first"), request.form.get("last"), hash, request.form.get("group")))
        conn.commit()

        # automatic login
        db.execute("SELECT * FROM users WHERE username = ?",(request.form.get("regusername"),))
        rows = db.fetchall()
        session["user_id"] = rows[0][0]

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("signup.html")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Password."""
    
    db.execute("SELECT role FROM users WHERE username=?", (session["user_id"],))
    rolex = db.fetchall()

    logged = session["user_id"]

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # query database for user
        db.execute("SELECT * FROM users WHERE username = ?",(session["user_id"],))
        rows = db.fetchall()

        # ensure old password is correct
        if not pwd_context.verify(request.form.get("oldpassword"), rows[0][3]):
            flash("Old Password is incorrect!")
            return render_template("change.html", **locals())
       
        # check password match
        if request.form.get("reppassword") != request.form.get("regpassword"):
            flash("New Password and Confirm Password must be same!")
            return render_template("change.html", **locals())
        
        # another check
        if pwd_context.verify(request.form.get("regpassword"), rows[0][3]):
            flash("New Password can't be same as Old Password!")
            return render_template("change.html", **locals())
        
        # password encryption
        hash = pwd_context.encrypt(request.form.get("regpassword"))
        
        # update changed password 
        db.execute("UPDATE users SET hash = ? WHERE username = ?",(hash, session["user_id"],))
        conn.commit()

        # redirect user to home page
        flash("Password changed successfully!")
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change.html", **locals())

@app.route("/write", methods=["GET", "POST"])
@login_required
def write():
    
    if request.method == 'POST':
        db.execute("INSERT INTO msgs VALUES(?, ?, DATETIME(current_timestamp, '+05 hours','+30 minutes'))", (session["user_id"], request.form.get("msg")))
        conn.commit()

        return redirect(url_for("index"))

    else:
        db.execute("SELECT role FROM users WHERE username=?", (session["user_id"],))
        rolex = db.fetchall()

        logged = session["user_id"]

        return render_template("write.html", **locals())

@app.route("/manage", methods=["GET", "POST"])
@login_required
def manage():

    if request.method == 'POST':
        usr_remove = request.form.get("remove")
        usr_admin = request.form.get("admin")

        if usr_remove is not None:
            db.execute("DELETE FROM users WHERE username=?", (usr_remove,))
            conn.commit()
        
        if usr_admin is not None:
            db.execute('UPDATE users SET role="Admin" WHERE username=?', (usr_admin,))
            conn.commit()

        return redirect(url_for("manage"))

    else:
        db.execute("SELECT role FROM users WHERE username=?", (session["user_id"],))
        rolex = db.fetchall()

        db.execute("SELECT grp FROM users WHERE username=?", (session["user_id"],))
        grp = db.fetchall()

        db.execute("SELECT username, first_name||' '||last_name AS name, role, doj FROM users WHERE grp=? ORDER BY role DESC, doj DESC", (grp[0][0],))
        users_list = db.fetchall()
        
        curr_user = session["user_id"]
        logged = session["user_id"]

        return render_template("manage.html", **locals())

@app.route("/create", methods=["GET", "POST"])
def create():

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # query database for username
        db.execute("SELECT * FROM users WHERE username = ?",(request.form.get("regusername"),))
        rows = db.fetchall()

        # query database group
        db.execute("SELECT * FROM users WHERE grp = ?",(request.form.get("group"),))
        g_rows = db.fetchall()

        # ensure username doesn't exist
        if len(rows) != 0:
            flash("This Username is already taken!")
            return render_template("create.html")

        # ensure group doesn't exist
        if len(g_rows) != 0:
            flash("This Group Name is already taken!")
            return render_template("create.html")
    
        # check password match
        if request.form.get("reppassword") != request.form.get("regpassword"):
            flash("Passwords don't match")
            return render_template("create.html")
        
        # password encryption
        hash = pwd_context.encrypt(request.form.get("regpassword"))
        
        #add user
        db.execute("INSERT INTO users(username, first_name, last_name, hash, grp, role, doj) VALUES(?, ?, ?, ?, ?, ?, DATETIME(current_timestamp, '+05 hours','+30 minutes'))",(request.form.get("regusername"), request.form.get("first"), request.form.get("last"), hash, request.form.get("group"), "Admin"))
        conn.commit()

        # automatic login
        db.execute("SELECT * FROM users WHERE username = ?",(request.form.get("regusername"),))
        rows = db.fetchall()
        session["user_id"] = rows[0][0]

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("create.html")       

if __name__=='__main__':
    app.run()