from sqlite3 import connect # Gives the ability to connect to sqlite3 databases
from flask import Flask, g, redirect, render_template, request # Allows the use of Flask, g, redirecting, HTML templates and requesting

app = Flask(__name__) # Initialises the app

def get_database():
    '''Connects to the database 'database.db' using getattr and returns the connection. If the database is not found, it connects manually.'''
    database_connection = getattr(g, '_database', None)
    if not bool(database_connection):
        database_connection = g._database = connect('database.db')
    return database_connection

@app.route('/')
def index():
    '''Renders the HTML template 'index.html' as the home page.'''
    return render_template('index.html')

@app.route('/account', methods=['GET', 'POST',])
def account():
    '''Renders the HTML template 'account.html'.'''
    return render_template('account.html')

@app.teardown_appcontext
def close_connection(exception):
    '''Checks if there is a connection to the database and closes it.'''
    database_connection = getattr(g, '_database', None)
    if bool(database_connection):
        database_connection.close()
    return

if __name__ == '__main__':
    app.run(debug=True)