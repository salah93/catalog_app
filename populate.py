from itertools import cycle

from app import session
from models import Item, Like, User, categories


def addItem(item, user):
    item = Item(user=user, **item)
    session.add(item)
    session.commit()
    return item


def addUser(email, name):
    user = session.query(User).get(email)
    if not user:
        user = User(email=email, name=name)
        session.add(user)
        session.commit()
    return user

if __name__ == '__main__':
    users_info = [{'email': 'abc@yahoo.com', 'name': 'abc'},
                  {'email': 'xyz@gmail.com', 'name': 'xyz'}]
    users = []
    for u in users_info:
        users.append(addUser(**u))
    items = []
    for u, c in zip(cycle(users), categories):
        item = {'title': '%s-item' % c, 'category': c,
                'picture': 'http://placekitten.com/g/200/300', 'description': 'my cool item'}
        items.append(addItem(item, u))
    for u in users:
        for i in items:
            if i.user != u:
                l = Like(item=i, user=u)
                session.add(l)
                session.commit()
