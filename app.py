"""
Leo Black
Phorems Flask Application
"""

from os import urandom # Provides random bytes of a certain length
from sqlite3 import connect # Gives the ability to connect to sqlite3 databases
from flask import Flask, g, redirect, render_template, request, session, url_for # Allows the use of Flask, g, redirecting with url_for, HTML templates, requesting and the session list
from flask_login import LoginManager # Allows the use of logging in and out via the flask login manager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash # Allows the use of hashing and checking hashed values
from config import Config

app = Flask(__name__) # Initialises the app
app.config.from_object(Config)
login_manager = LoginManager(app) # Handles whether or not the user is logged in
database = SQLAlchemy(app)

import model


@login_manager.user_loader
def load_user(user_id):
    return

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

@app.route('/test')
def test():
    name = model.User.query.all()
    value = model.User(username='jack', password='Jack Jones')
    database.session.add(value)
    database.session.commit()
    return render_template('index.html', pizza=name)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    '''Allows users to sign up with a unique username and password.'''
    if request.method == 'GET': # Checks if values have not yet been inputted and redirects to the signup page if not
        return render_template('signup.html')
    error = None
    new_username = request.form['username'] # Gets the inputted username value
    new_password = request.form['password'] # Gets the inputted password value
    if new_username == '' or new_password == '': # Checks if either the username or password are left blank
        error = 'Please enter a username and a password.'
        return render_template('signup.html', error=error) # Starts again, showing the error message
    user_already_exists = model.User.query.filter_by(username=new_username) # Checks if the username is taken
    if list(user_already_exists):
        error = 'Username already taken. Please try again.'
        return render_template('signup.html', error=error)
    database.session.add(model.User(username=new_username, password=generate_password_hash(new_password, 'SHA256'))) # Adds the username and password into the database and hashes the password using the method SHA256
    database.session.commit() # Commits and stores the values in the database
    global user_id # Allows the variable user_id to be used anywhere in the program
    user_id = model.User.query.filter_by(username=new_username).first()
    session['logged_in'] = True # Sets the user's status as logged in
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Checks if the login credentials are correct, logs in and redirects to the account page.'''
    if request.method == 'GET':
        return render_template('login.html')
    error = None
    username = request.form['username'] # Gets the inputted username value
    password = request.form['password'] # Gets the inputted password value
    user = model.User.query.filter_by(username=username) # Gets the user's stored info
    if list(user): # Checks if the username entered exists in the database
        if check_password_hash(user[0].password, password): # Checks if the password entered is correct
            session['logged_in'] = True # Sets the user's status as logged in
            global user_id # Allows the variable user_id to be used anywhere in the program
            user_id = user[0].id
            return redirect(url_for('index'))
    if username == '' and password == '': # Checks if nothing is inputted and doesn't show an error
        return redirect(url_for('index'))
    if username == '' or password == '' or username.isspace():
        error = 'Please enter a valid username and password.' # Checks if nothing is inputted in one of the values or if the username is just whitespace
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
    post_list = get_posts()
    return render_template('index.html', posts=post_list, user_id=user_id) # Renders 'index.html' and prints the list of posts

def get_posts(filter_by=None):
    '''Gets the information for each post in the database, putting the most recent post first and filtering by tags if specified.'''
    if filter_by:
        posts = model.Post.query.filter(model.Post.tag.like("%{}%".format(filter_by))).order_by(model.Post.id.desc()) # Gets all the posts in the database with the chosen tag
    else:
        posts = model.Post.query.order_by(model.Post.id.desc()) # Gets all the posts in the database
    return posts

@app.route('/post/fail', methods=['GET', 'POST']) # The user will only ever see the URL /post/fail if the post wasn't accepted, the function isn't solely for an error page
def posts():
    '''Adds the inputted post to the database if both values are entered.'''
    if 'logged_in' not in session:
        return redirect(url_for('index'))
    cursor = get_database().cursor()
    try: # Checks if the user typed in the post/fail url without submitting any values
        title = request.form['title'] # Gets the inputted title value
        body = request.form['post'] # Gets the inputted body text value
        tags = request.form['tags'] # Gets the inputted tags values (if added)
    except KeyError:
        return redirect(url_for('index'))
    if title == '' or body == '' or title.isspace() or body.isspace(): # Checks if either value were left blank or are only spaces
        error = 'Please enter a valid title and body text.'
        post_list = get_posts()
        return render_template('index.html', posts=post_list, error=error, user_id=user_id)
    if bool(tags) and not tags.isspace(): # Checks if there are any tags on the post
        sql_query = 'INSERT INTO Post (title, body, author, tag) VALUES (?,?,?,?)' # Adds a post with a title, body text, author and tags value into the database
        cursor.execute(sql_query, (title, body, user_id, tags))
    else:
        sql_query = 'INSERT INTO Post (title, body, author) VALUES (?,?,?)' # Adds a post with a title, body text and author value into the database 
        cursor.execute(sql_query, (title, body, user_id))
    get_database().commit() # Saves the new post in the database
    return redirect(url_for('index'))
    
@app.route('/delete', methods=['GET','POST'])
def delete():
    '''Allows users to delete their own posts after confirmation.'''
    if 'logged_in' not in session: # Sends users back to the login page if they haven't signed in
        return redirect(url_for('index'))
    if request.method == 'POST':
        cursor = get_database().cursor()
        post_id = int(request.form['post_id']) # Gets the ID of the specified post to delete
        sql_query = 'DELETE FROM Post WHERE id = ?'
        cursor.execute(sql_query, (post_id,))
        get_database().commit() # Saves the change to the database
    return redirect(url_for('index'))

@app.route('/account')
def account():
    '''Renders the HTML template 'account.html' if the user is logged in.'''
    if 'logged_in' in session:
        return render_template('account.html')
    return redirect(url_for('index'))

@app.route('/filter-by-<tag>')
def tag_filter(tag):
    '''Lists all posts under a certain tag.'''
    if 'logged_in' not in session:
        return redirect(url_for('index'))
    post_list = get_posts(tag)
    return render_template('filter.html', tag=tag.lower(), posts=post_list, user_id=user_id)

if __name__ == '__main__': # Runs the application and sets the secret key to a random 12 byte object
    app.secret_key = urandom(12)
    app.run(debug=True)
