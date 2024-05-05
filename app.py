from flask import Flask, render_template, request, redirect, url_for, session
from bson.objectid import ObjectId
import bcrypt
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import urllib
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)
app.secret_key =  os.getenv("SECRET_KEY")


uri =  os.getenv("MONGO_URL")


client = MongoClient(uri, server_api=ServerApi('1'))
db = client["admin_panel"]

def logged_in():
    return "username" in session


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")

        user = db.users.find_one({"username": username})

        if user and bcrypt.checkpw(password, user["password"]):
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            return "Invalid username/password combination"

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")

        existing_user = db.users.find_one({"username": username})

        if existing_user:
            return "Username already exists"

        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        db.users.insert_one({"username": username, "password": hashed})
        session["username"] = username
        return redirect(url_for("dashboard"))

    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not logged_in():
        return redirect(url_for("login"))

    instances = db.instances.find()
    return render_template("dashboard.html", instances=instances)

if __name__ == "__main__":
    app.run(debug=True)
