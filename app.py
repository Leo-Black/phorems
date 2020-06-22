"""
Leo Black
Phorem Flask Application
"""

from sqlite3 import connect # Gives the ability to connect to sqlite3 databases
from flask import Flask, g, redirect, url_for, render_template, request, session # Allows the use of Flask, g, redirecting with url_for, HTML templates, requesting and the session list
from flask_login import LoginManager # Allows the use of logging in and out via the flask login manager
from os import urandom # Provides random bytes of a certain length
from werkzeug.security import generate_password_hash, check_password_hash # Allows the use of hashing and checking hashed values

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
    '''Allows users to sign up with a unique username and password.'''
    if request.method == 'GET': # Checks if values have not yet been inputted and redirects to the signup page if not
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
    cursor.execute(sql_query, (new_username, generate_password_hash(new_password, 'SHA256'))) # Executes the query and hashes the password using the method SHA256
    get_database().commit() # Commits and stores the values in the database
    sql_query = 'SELECT ID FROM Users WHERE Username = ?'
    cursor.execute(sql_query, (new_username,))
    global user_id # Allows the variable user_id to be used anywhere in the program
    user_id = cursor.fetchall()[0][0]
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
    sql_query = 'SELECT ID, Password FROM Users WHERE Username = ?' # Returns the user with the inputted username value
    cursor.execute(sql_query, (username,))
    results = cursor.fetchall()
    if bool(results): # Checks if the username entered is correct
        if check_password_hash(results[0][1], password): # Checks if the password entered is correct
            session['logged_in'] = True # Sets the user's status as logged in
            global user_id # Allows the variable user_id to be used anywhere in the program
            user_id = results[0][0]
            return redirect(url_for('index'))
    if username == '' and password == '': # Checks if nothing is inputted and doesn't show an error
        return redirect(url_for('index'))
    if username == '' or password == '':
        error = 'Please enter a username and a password.' # Checks if nothing is inputted in one of the values
        return render_template('login.html', error=error)
    error = 'Incorrect Credentials'
    return render_template('login.html', error=error) # Starts again and flashes the error message

@app.route('/logout')
def logout():
    '''Allows users to log out via the accounts page.'''
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
def index():
    '''Renders the index page if the user is logged in.'''
    if 'logged_in' not in session:
        return render_template('login.html')
    cursor = get_database().cursor()
    sql_query = 'SELECT Posts.Title, Posts.Body, Users.Username FROM Posts INNER JOIN Users ON Posts.Creator = Users.ID' # Gets the post's title, body text and author from the database
    cursor.execute(sql_query)
    results = cursor.fetchall()
    return render_template('index.html', posts=results) # Renders 'index.html' and prints the list of posts

@app.route('/post/fail', methods=['GET', 'POST'])
def posts():
    '''Adds the inputted post to the database if both values are entered.'''
    if 'logged_in' not in session:
        return redirect(url_for('index'))
    cursor = get_database().cursor()
    title = request.form['title'] # Gets the inputted title value
    body = request.form['post'] # Gets the inputted body text value
    if title == '' or body == '': # Checks if either value were left blank
        error = 'Please enter a title and body text.'
        sql_query = 'SELECT Posts.Title, Posts.Body, Users.Username FROM Posts INNER JOIN Users ON Posts.Creator = Users.ID' # Gets the post's title, body text and author from the database
        cursor.execute(sql_query)
        results = cursor.fetchall()
        return render_template('index.html', posts=results, error=error)
    sql_query = 'INSERT INTO Posts (Title, Body, Creator) VALUES (?,?,?)' # Adds a post with a title, body text and author value into the database 
    cursor.execute(sql_query, (title, body, user_id))
    get_database().commit()
    return redirect(url_for('index'))


@app.route('/account')
def account():
    '''Renders the HTML template 'account.html' if the user is logged in.'''
    if 'logged_in' in session:
        return render_template('account.html')
    return redirect(url_for('index'))

if __name__ == '__main__': # Runs the application and sets the secret key to a random 12 byte object
    app.secret_key = urandom(12)
    app.run(debug=True)