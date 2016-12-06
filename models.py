from datetime import datetime

from sqlalchemy import Column, ForeignKey, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()
categories = ['football', 'american football', 'baseball', 'golf', 'rock climbing', 'skiing', 'basketball', 'swimming', 'running']


class User(Base):
    __tablename__ = 'user'
    email = Column(String(250), nullable=False, primary_key=True)
    picture = Column(String(250))
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return {'id': self.id,
                'email': self.email,
                'picture': self.picture,
                'name': self.name}


class Item(Base):
    __tablename__ = 'item'
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    title = Column(String(25), nullable=False)
    category = Column(String(25), nullable=False)
    description = Column(Text, nullable=False)
    date_added = Column(DateTime, default=datetime.utcnow)
    picture = Column(String(250))
    user_email = Column(Integer, ForeignKey('user.email'))
    user = relationship(User)

    @property
    def serialize(self):
        return {'id': self.id,
                'title': self.title,
                'category': self.category,
                'picture': self.picture,
                'author': self.user_email,
                'date_added': self.date_added.strftime('%m-%d-%y-%s'),
                'description': self.description}


class Like(Base):
    __tablename__ = 'like'
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey('item.id'))
    item = relationship(Item)
    user_email = Column(Integer, ForeignKey('user.email'))
    user = relationship(User)


# Create an engine that stores data in the local directory's
# catalog_app.db file.
engine = create_engine('sqlite:///catalog_app.db')

# Create all tables in the engine. This is equivalent to "Create Table"
# statements in raw SQL.
Base.metadata.create_all(engine)
