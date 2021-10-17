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
  comment = database.Column(database.String())
  author = database.Column(database.Integer, database.ForeignKey('User.id'))
  
class Comment(database.Model):
  __tablename__ = 'Comment'
  id = database.Column(database.Integer, primary_key=True)
  body = database.Column(database.String())
  post = database.Column(database.Integer, database.ForeignKey('Post.id'))
  author = database.Column(database.Integer, database.ForeignKey('User.id'))