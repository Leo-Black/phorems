"""
Leo Black
Phorems Flask Application
"""

from os import urandom  # Provides random bytes of a certain length

from flask import Flask, g, redirect, render_template, request, session, url_for # Allows the use of Flask, g, redirecting with url_for, HTML templates, requesting and the session list
from flask_login import LoginManager  # Allows the use of logging in and out via the flask login manager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash # Allows the use of hashing and checking hashed values

from config import Config

app = Flask(__name__) # Initialises the app
app.config.from_object(Config)
login_manager = LoginManager(app) # Handles whether or not the user is logged in
database = SQLAlchemy(app, session_options={"autoflush": False}) # Sets up the database and keeps it from randomly flushing and causing errors
from app import database

import model


@login_manager.user_loader
def load_user(user_id):
    '''Allows the use of the login manager.'''
    return

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
    user = model.User.query.filter_by(username=new_username) # Gets the user's stored info
    global user_id # Allows the variable user_id to be used anywhere in the program
    user_id = user[0].id
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
    post_info = get_posts()
    return render_template('index.html', posts=post_info[0], comments=post_info[1], user_id=user_id) # Renders 'index.html' and prints the list of posts and comments

@app.route('/search', methods=['GET', 'POST'])
def search():
    '''Returns all the posts and comments including the specified search value.'''
    if 'logged_in' not in session or request.method != 'POST': # Checks if the user typed in the post/fail url without submitting any values or logging in
        return redirect(url_for('index'))
    search_by = request.form['search']
    if not search_by or search_by.isspace(): # Checks if the value was left blank
        return redirect(url_for('index'))
    post_info = get_posts(search_by=search_by)
    return render_template('search.html', search=search_by, posts=post_info[0], comments=post_info[1], user_id=user_id)

def get_posts(filter_by=None, search_by=None):
    '''Gets the information for each post in the database, putting the most recent post first and filtering by tags or a search query if specified.'''
    order = model.Post.id.desc() # Sorts the posts by most recent first
    if filter_by: # Checks if user is searching by tag
        filter_by = model.Post.tag.like("%{}%".format(filter_by)) # Only gets posts with the chosen tag
        posts = database.session.query(model.Post, model.User.username).filter(model.Post.author==model.User.id).filter(filter_by).order_by(order).all() # Gets posts and their authors from the database with the chosen tag
    if search_by: # Checks if the user is searching via query
        posts = database.session.query(model.Post, model.User.username).filter(model.Post.author==model.User.id).filter(model.Post.title.like("%{}%".format(search_by)) | model.Post.body.like("%{}%".format(search_by)) | model.Post.tag.like("%{}%".format(search_by)) | model.Post.comment.like("%{}%".format(search_by))).order_by(order).all() # Gets all posts that include the search value
    else:
        posts = database.session.query(model.Post, model.User.username).filter(model.Post.author==model.User.id).order_by(order).all() # Gets each post and the user that wrote it
    for post in posts:
        if post[0].comment and type(post[0].comment) == str: # Checks if the values have already been turned into a list
            post[0].comment = list(map(int, post[0].comment.split())) # Turns the comment id values into a list of integers 
    comments = database.session.query(model.Comment, model.User.username).filter(model.Comment.author==model.User.id).all() # Gets each comment and the user that wrote it
    return posts, comments

@app.route('/post/fail', methods=['GET', 'POST']) # The user will only ever see the URL /post/fail if the post wasn't accepted, the function isn't solely for an error page
def posts():
    '''Adds the inputted post to the database if both values are entered.'''
    if 'logged_in' not in session or request.method != 'POST': # Checks if the user typed in the post/fail url without submitting any values or logging in
        return redirect(url_for('index'))
    title = request.form['title'] # Gets the inputted title value
    body = request.form['post'] # Gets the inputted body text value
    tags = request.form['tags'] # Gets the inputted tags values (if added)
    if not title or not body or title.isspace() or body.isspace(): # Checks if either value were left blank or are only spaces
        error = 'Please enter a valid title and body text.'
        post_info = get_posts()
        return render_template('index.html', posts=post_info[0], comments=post_info[1], user_id=user_id, error=error)
    if tags.isspace(): # Checks if there are any tags on the post
        tags = None
    database.session.add(model.Post(title=title, body=body, author=user_id, tag=tags.lower())) # Adds a post with title, body text, author and tag (if added) values into the database
    database.session.commit() # Saves the new post in the database
    return redirect(url_for('index'))

@app.route('/comment/fail', methods=['GET', 'POST']) # The user will only ever see the URL /comment/fail if the comment wasn't accepted, the function isn't solely for an error page
def add_comment():
    '''Adds the inputted comment to the database if not left blank.'''
    if 'logged_in' not in session or request.method != 'POST': # Sends users back to the login page if they haven't signed in
        return redirect(url_for('index'))
    text = request.form['text']
    post_id = int(request.form['post_id'])
    if not text or text.isspace():
        error = 'Please enter a valid comment.'
        post_info = get_posts()
        return render_template('index.html', posts=post_info[0], comments=post_info[1], user_id=user_id, error=error)
    database.session.add(model.Comment(body=text, author=user_id, post=post_id)) # Adds the comment to the database
    database.session.commit()
    comment_post = model.Post.query.filter_by(id=post_id).first() # Gets the info of the post the comment was made under
    if not comment_post.comment: # Checks if the post has any other comments
        comment_post.comment = ' {} '.format(model.Comment.query.order_by(model.Comment.id.desc()).first().id) # Sets the post's comment value to the id of its comment if no other comments exist, adding spaces to differentiate comments
    else:
        comment_post.comment = "{}{} ".format(comment_post.comment, model.Comment.query.order_by(model.Comment.id.desc()).first().id) # Adds the comment id to the end of the list of comments under the post
    database.session.add(comment_post)
    database.session.commit() # Saves the info to the database
    return redirect(url_for('index'))
        

@app.route('/delete', methods=['GET','POST'])
def delete():
    '''Allows users to delete their own posts after confirmation.'''
    if 'logged_in' not in session: # Sends users back to the login page if they haven't signed in
        return redirect(url_for('index'))
    if request.method == 'POST':
        post_id = int(request.form['post_id'])
        database.session.query(model.Post).filter_by(id=post_id).delete() # Deletes the post with the specified id
        database.session.commit() # Saves the change to the database
    return redirect(url_for('index'))

@app.route('/filter-by-<tag>')
def tag_filter(tag):
    '''Lists all posts under a certain tag.'''
    if 'logged_in' not in session:
        return redirect(url_for('index'))
    post_info = get_posts(filter_by=tag)
    return render_template('filter.html', tag=tag.lower(), posts=post_info[0], comments=post_info[1], user_id=user_id)

if __name__ == '__main__': # Runs the application and sets the secret key to a random 12 byte object
    app.secret_key = urandom(12)
    app.run(debug=True)
