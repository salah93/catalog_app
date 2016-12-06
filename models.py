from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()
categories = []


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return {'id': self.id,
                'email': self.email}


class Item(Base):
    __tablename__ = 'item'
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    title = Column(String(25), nullable=False)
    category = Column(String(25), nullable=False)
    description = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {'id': self.id,
                'title': self.title,
                'category': self.category,
                'description': self.description}


class Like(Base):
    __tablename__ = 'like'
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey('item.id'))
    item = relationship(Item)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


# Create an engine that stores data in the local directory's
# catalog_app.db file.
engine = create_engine('sqlite:///catalog_app.db')

# Create all tables in the engine. This is equivalent to "Create Table"
# statements in raw SQL.
Base.metadata.create_all(engine)
