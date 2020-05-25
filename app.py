from sqlite3 import connect # Gives the ability to connect to sqlite3 databases
from flask import Flask, g, redirect, render_template, request, url_for, session, flash, abort # Allows the use of Flask, g, redirecting, HTML templates and requesting
from flask_login import LoginManager # Allows the use of logging in and out via the flask login manager
import os

app = Flask(__name__) # Initialises the app
login = LoginManager(app)

def get_database():
    '''Connects to the database 'database.db' using getattr and returns the connection. If the database is not found, it connects manually.'''
    database_connection = getattr(g, '_database', None)
    if not bool(database_connection):
        database_connection = g._database = connect('database.db')
    return database_connection

@app.teardown_appcontext
def close_connection(exception):
    '''Checks if there is a connection to the database and closes it.'''
    database_connection = getattr(g, '_database', None)
    if bool(database_connection):
        database_connection.close()
    return

@app.route('/')
def index():
    '''Renders the HTML template 'index.html' as the home page if the user is logged in.'''
    if 'logged_in' not in session:
        return render_template('login.html')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Checks if the login credentials are correct, logs in and redirects to the account page.'''
    if request.method == 'POST': 
        if request.form['password'] == 'admin' and request.form['username'] == 'admin':
            session['logged_in'] = True
            return redirect(url_for('index'))
        flash('Incorrect Credentials')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/account')
def account():
    '''Renders the HTML template 'account.html'.'''
    return render_template('account.html')

if __name__ == '__main__': # Runs the application and sets the secret key to a random 12 byte object
    app.secret_key = os.urandom(12)
    app.run(debug=True)