from app import database

class User(database.Model):
  __tablename__ = 'User'
  id = database.Column(database.Integer, primary_key=True)
  username = database.Column(database.String())
  password = database.Column(database.String())

class Post(database.Model):
  __tablename__ = 'Post'
  id = database.Column(database.Integer, primary_key=True)
  title = database.Column(database.String())
  body = database.Column(database.String())
  tag = database.Column(database.String())
  comment = database.Column(database.Integer)
  author = database.relationship('User', back_populates='id')

class Comment(database.Model):
  __tablename__ = 'Comment'
  id = database.Column(database.Integer, primary_key=True)
  body = database.Column(database.String())
  code = database.Column(database.String())
  post = database.relationship('Post', back_populates='id')
  author = database.relationship('User', back_populates='id')