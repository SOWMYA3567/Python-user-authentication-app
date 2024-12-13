from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Simulated database (use a real database in production)
users_db = {}

# User class
class User(UserMixin):
    def __init__(self, id, username, password, role="user"):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

    def get_role(self):
        return self.role

@login_manager.user_loader
def load_user(user_id):
    return users_db.get(user_id)

@app.route("/")
def index():
    return "Welcome! Go to /login or /register."

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "user")  # Default role is "user"

        if username in [user.username for user in users_db.values()]:
            flash("Username already exists!")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password, method="bcrypt")
        user_id = str(len(users_db) + 1)
        new_user = User(id=user_id, username=username, password=hashed_password, role=role)
        users_db[user_id] = new_user

        flash("Registration successful! You can now log in.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Find the user by username
        user = next((u for u in users_db.values() if u.username == username), None)
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return f"Hello, {current_user.username}! You are logged in as {current_user.get_role()}."

@app.route("/admin")
@login_required
def admin():
    if current_user.get_role() != "admin":
        flash("Access denied. Admins only!")
        return redirect(url_for("dashboard"))
    return "Welcome to the admin page!"

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)


