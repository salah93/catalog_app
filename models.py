from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return {'id': self.id,
                'email': self.email}


class Restaurant(Base):
    __tablename__ = 'restaurant'
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    name = Column(String(250))
    address = Column(String(250))

    @property
    def serialize(self):
        return {'id': self.id,
                'name': self.name,
                'address': self.address}


class MenuItem(Base):
    __tablename__ = 'menu_item'
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    name = Column(String(250))
    course = Column(String(250))
    price = Column(Integer, nullable=False)
    restaurant_id = Column(Integer, ForeignKey('restaurant.id'))
    restaurant = relationship(Restaurant)

    @property
    def serialize(self):
        return {'id': self.id,
                'name': self.name,
                'course': self.course,
                'price': self.price,
                'restaurant': self.restaurant.name}


class Like(Base):
    __tablename__ = 'like'
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    menu_item_id = Column(Integer, ForeignKey('menu_item.id'))
    menu_item = relationship(MenuItem)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


# Create an engine that stores data in the local directory's
# restaurant_app.db file.
engine = create_engine('sqlite:///restaurant_app.db')

# Create all tables in the engine. This is equivalent to "Create Table"
# statements in raw SQL.
Base.metadata.create_all(engine)
