from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from passlib.apps import custom_app_context as pwd_context
from tempfile import mkdtemp
from functools import wraps
from flask_mysqldb import MySQL
import os

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

app.config["MYSQL_USER"] = ''
app.config["MYSQL_PASSWORD"] = ''
app.config["MYSQL_DB"] = ''
app.config["MYSQL_HOST"] = 'localhost'
mysql=MySQL(app)

def execute_db(query,args=()):
    cur=mysql.connection.cursor()
    cur.execute(query,args)
    mysql.connection.commit()
    cur.close()

def query_db(query,args=(),one=False):
    cur=mysql.connection.cursor()
    result=cur.execute(query,args)
    if result>0:
        values=cur.fetchall()
        cur.close()
        return values
    cur.close()
    return ()

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

    rolex = query_db("SELECT role FROM users WHERE username=%s", (session["user_id"],))

    grp = query_db("SELECT grp FROM users WHERE username=%s", (session["user_id"],))

    msgs = query_db("SELECT msgs.username, first_name||' '||last_name AS name, role, msg, time FROM msgs,users WHERE msgs.username = users.username AND grp=%s ORDER BY time DESC",(grp[0][0],))

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
        rows = query_db("SELECT * FROM users WHERE username = %s",(request.form.get("username"),))

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
        rows = query_db("SELECT * FROM users WHERE username = %s",(request.form.get("regusername"),))

        # ensure username doesn't exist
        if len(rows) != 0:
            flash("This Username is already taken!")
            return render_template("signup.html")
        
        # query database for group
        group_chk = query_db("SELECT * FROM users WHERE grp = %s",(request.form.get("group"),))

        # ensure group exists
        if len(group_chk) == 0:
            flash("This Group doesn't exist!")
            return render_template("signup.html")
       
        # check password match
        if request.form.get("reppassword") != request.form.get("regpassword"):
            flash("Passwords don't match")
            return render_template("signup.html")
        
        # password encryption
        hash = pwd_context.encrypt(request.form.get("regpassword"))
        
        #add user
        execute_db("INSERT INTO users(username, first_name, last_name, hash, grp, doj) VALUES(%s, %s, %s, %s, %s, DATETIME(current_timestamp, '+05 hours','+30 minutes'))",(request.form.get("regusername"), request.form.get("first"), request.form.get("last"), hash, request.form.get("group")))

        # automatic login
        rows = query_db("SELECT * FROM users WHERE username = %s",(request.form.get("regusername"),))
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
    
    rolex = query_db("SELECT role FROM users WHERE username=%s", (session["user_id"],))

    logged = session["user_id"]

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # query database for user
        rows = query_db("SELECT * FROM users WHERE username = %s",(session["user_id"],))

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
        execute_db("UPDATE users SET hash = %s WHERE username = %s",(hash, session["user_id"],))

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
        execute_db("INSERT INTO msgs VALUES(%s, %s, now())", (session["user_id"], request.form.get("msg")))

        return redirect(url_for("index"))

    else:
        rolex = query_db("SELECT role FROM users WHERE username=%s", (session["user_id"],))

        logged = session["user_id"]

        return render_template("write.html", **locals())

@app.route("/manage", methods=["GET", "POST"])
@login_required
def manage():

    if request.method == 'POST':
        usr_remove = request.form.get("remove")
        usr_admin = request.form.get("admin")

        if usr_remove is not None:
            execute_db("DELETE FROM users WHERE username=%s", (usr_remove,))
        
        if usr_admin is not None:
            execute_db('UPDATE users SET role="Admin" WHERE username=%s', (usr_admin,))

        return redirect(url_for("manage"))

    else:
        rolex = query_db("SELECT role FROM users WHERE username=%s", (session["user_id"],))

        grp = query_db("SELECT grp FROM users WHERE username=%s", (session["user_id"],))

        users_list = query_db("SELECT username, first_name||' '||last_name AS name, role, doj FROM users WHERE grp=%s ORDER BY role DESC, doj DESC", (grp[0][0],))
        
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
        rows = query_db("SELECT * FROM users WHERE username = %s",(request.form.get("regusername"),))

        # query database group
        g_rows = query_db("SELECT * FROM users WHERE grp = %s",(request.form.get("group"),))

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
        execute_db("INSERT INTO users(username, first_name, last_name, hash, grp, role, doj) VALUES(%s, %s, %s, %s, %s, %s, now())",(request.form.get("regusername"), request.form.get("first"), request.form.get("last"), hash, request.form.get("group"), "Admin"))

        # automatic login
        rows = query_db("SELECT * FROM users WHERE username = %s",(request.form.get("regusername"),))
        session["user_id"] = rows[0][0]

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("create.html")       
    
if __name__ == "__main__":    
    app.secret_key = os.urandom(24)
    app.run(host = "127.0.0.1",debug=True,port=5000)