from app import database

PostTag = database.Table('PostTag', database.Model.metadata,
  database.Column('postid', database.Integer, database.ForeignKey('Post.id')),
  database.Column('tagid', database.Integer, database.ForeignKey('Tag.id')),
)

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
  user = database.Column(database.Integer, database.ForeignKey('User.id'))

  user_name = database.relationship('User', backref='Post')
  tag = database.relationship('Tag', secondary=PostTag, back_populates='post')

class Tag(database.Model):
  __tablename__ = 'Tag'
  id = database.Column(database.Integer, primary_key=True)
  tag = database.Column(database.String())

  post = database.relationship('Post', secondary=PostTag, back_populates='tag')

class Comment(database.Model):
  __tablename__ = 'Comment'
  id = database.Column(database.Integer, primary_key=True)
  comment = database.Column(database.String())
  post = database.Column(database.Integer, database.ForeignKey('Post.id'))
  user = database.Column(database.Integer, database.ForeignKey('User.id'))

  user_name = database.relationship('User', backref='Comment')