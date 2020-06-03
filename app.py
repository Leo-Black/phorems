from sqlite3 import connect # Gives the ability to connect to sqlite3 databases
from flask import Flask, g, redirect, render_template, request, url_for, session, flash, abort # Allows the use of Flask, g, redirecting, HTML templates and requesting
from flask_login import LoginManager # Allows the use of logging in and out via the flask login manager
from os import urandom

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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    '''Allows users to sign up with a username and password if the username is unique and neither values are blank.'''
    if request.method != 'POST': # Checks if values have not yet been inputted and redirects to the signup page if not
        return render_template('signup.html')
    error = None
    cursor = get_database().cursor() # Sets up the SQL cursor
    new_username = request.form['username'] # Gets the inputted username value
    new_password = request.form['password'] # Gets the inputted password value
    if new_username == '' or new_password == '': # Checks if either the username or password are left blank
        error = 'Please enter a username and a password.'
        return render_template('signup.html', error=error) # Starts again, showing the error message
    sql_query = 'SELECT Username FROM Users WHERE Username = ?' # Returns all users with the same username inputted
    cursor.execute(sql_query, (new_username,))
    if bool(cursor.fetchall()): # Finds if there are any other users in the database with the same username
        error = 'Username already taken. Please try again.'
        return render_template('signup.html', error=error)
    sql_query = 'INSERT INTO Users (Username, Password) VALUES (?,?)' # Adds the username and password into the database
    cursor.execute(sql_query, (new_username, new_password))
    get_database().commit() # Commits and stores the values in the database
    session['logged_in'] = True # Sets the user's status as logged in
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Checks if the login credentials are correct, logs in and redirects to the account page.'''
    if request.method == 'GET':
        return render_template('login.html')
    error = None
    cursor = get_database().cursor() # Sets up the SQL cursor
    username = request.form['username'] # Gets the inputted username value
    password = request.form['password'] # Gets the inputted password value
    sql_query = 'SELECT ID FROM Users WHERE Username = ? AND Password = ?' # Returns the user with the inputted username and password values
    cursor.execute(sql_query, (username, password))
    result = cursor.fetchall()
    if bool(result): # Checks if there is a user with the inputted values
        session['logged_in'] = True # Sets the user's status as logged in
        return redirect(url_for('index'))
    if username == '' and password == '': # Checks if nothing is inputted and doesn't show an error
        return redirect(url_for('index'))
    error = 'Incorrect Credentials'
    return render_template('login.html', error=error) # Starts again and flashes the error message

@app.route('/logout')
def logout():
    '''Allows users to log out via the accounts page.'''
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/')
def index():
    '''Renders the HTML template 'index.html' as the home page if the user is logged in.'''
    if 'logged_in' not in session:
        return render_template('login.html', error=None)
    return render_template('index.html')

@app.route('/account')
def account():
    '''Renders the HTML template 'account.html' if the user is logged in.'''
    if 'logged_in' in session: # Checks if the user is logged in
        return render_template('account.html')
    return redirect(url_for('index'))

if __name__ == '__main__': # Runs the application and sets the secret key to a random 12 byte object
    app.secret_key = urandom(12)
    app.run(debug=True)