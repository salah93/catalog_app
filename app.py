'''
simple app demonstrating CRUD
'''

from functools import wraps

from flask import (Flask, abort, flash, render_template,
                   redirect, url_for, request, jsonify,
                   session as web_session)
from sqlalchemy.orm import sessionmaker

from models import Item, User, Like, engine, Base, categories
from utility import random_string


Base.metadata.bind = engine
dbsession = sessionmaker(bind=engine)
session = dbsession()
app = Flask(__name__)


def confirm_login(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner


def is_logged_in():
    return 'logged_in' in web_session


@app.route('/', methods=['GET'])
def home():
    ''' this view will list all the categories and latest item
        once you log in, you can add items
    '''
    latest = session.query(Item).order_by(Item.date_added.desc())[:5]
    return render_template('home_page.html', latest=latest)


@app.route('/catalog/<category>/items', methods=['GET'])
def category_page(category):
    '''this view will show the items for a specific category '''
    if category not in categories:
        return render_template('no_such.html', object='category'), 400
    items = session.query(Item).filter_by(category=category).order_by(Item.title)
    return render_template('category_page.html', category=category, items=items)


@app.route('/catalog/<category>/<title>', methods=['GET'])
def item_page(category, title):
    '''this view will show an item in detail
        once you log in, you can edit item
    '''
    if category not in categories:
        return render_template('no_such.html', object='category'), 400
    # TODO: what to do if multiple items have same name & same category
    item = session.query(Item).filter_by(category=category, title=title).first()
    if not item:
        return render_template('no_such.html', object='item'), 400
    editable = item.user_email == web_session.get('email', '')
    return render_template('item_page.html', editable=editable, **item.serialize)


@app.route('/catalog/add', methods=['POST', 'GET'])
@confirm_login
def add_item():
    ''' this view will add an item to the database
        only if logged in
    '''
    if request.method == 'GET':
        return render_template('item_form.html', url=request.path, header='Add an item')
    category = request.form.get('category', '')
    description = request.form.get('description', '').strip()
    title = request.form.get('title', '').strip()
    if not (category and title and description) or category not in categories:
        flash('add failed')
        return redirect(url_for('home'))
    item = Item(title=title, description=description,
                category=category, user_email=web_session['email'])
    session.add(item)
    session.commit()
    return redirect(url_for('home'))


@app.route('/catalog/<title>/edit', methods=['POST', 'GET'])
@confirm_login
def edit_item(title):
    ''' this view will edit an item
        only if logged in
        only if you added the item
    '''
    item = session.query(Item).filter_by(title=title).first()
    if not item:
        return render_template('no_such.html', object='item'), 400
    if item.user_email != web_session['email']:
        flash('you can only edit your own items')
        return redirect(url_for('home'))
    if request.method == 'GET':
        return render_template('item_form.html',
                               header='Edit %s' % title,
                               url=request.path,
                               **item.serialize)
    category = request.form.get('category', '')
    description = request.form.get('description', '').strip()
    new_title = request.form.get('title', '').strip()
    if not (category and new_title and description) or category not in categories:
        flash('edit failed')
        return redirect(url_for('home'))
    item.title = new_title
    item.category = category
    item.description = description
    session.add(item)
    session.commit()
    return redirect(url_for('home'))


@app.route('/catalog/<title>/delete', methods=['POST'])
@confirm_login
def delete_item(title):
    ''' this view will delete an item
        only if logged in
        only if you added the item
    '''
    item = session.query(Item).filter_by(title=title).first()
    if not item:
        return jsonify(delete=False, error_msg='no such item')
    if item.user_email != web_session['email']:
        return jsonify(delete=False, error_msg='you can only delete your own items')
    session.delete(item)
    session.commit()
    return jsonify(delete=True)


@app.route('/login', methods=['POST', 'GET'])
def login():
    '''this view will login the user'''
    pass


@app.route('/logout', methods=['POST'])
def logout():
    '''this view will be used to log out the user'''
    web_session.pop('logged_in', None)
    return redirect(url_for('home'))


@app.route('/catalog.json')
def json_catalog():
    '''this view returns all items in json view'''
    items = session.query(Item)
    return jsonify(items=[i.serialize for i in items])


@app.route('/profile', methods=['GET'])
@confirm_login
def profile():
    ''' this view will list all the favorites for a user'''
    user = session.query(User).get(web_session['email'])
    favorites = (l.item for l in session.query(Like).filter_by(user=user))
    items = session.query(Item).filter_by(user=user)
    return render_template('profile.html', favorites=favorites, items=items, **user.serialize)


@app.before_request
def csrf_protect():
    ''' protect against csrf attacks
        taken from flask snippets http://flask.pocoo.org/snippets/3/,
        add this to all forms:
        <input name=_csrf_token type=hidden value="{{ csrf_token() }}">
    '''
    if request.method == 'POST':
        token = web_session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)


def generate_csrf_token():
    if '_csrf_token' not in web_session:
        web_session['_csrf_token'] = random_string()
    return web_session['_csrf_token']


if __name__ == '__main__':
    app.secret_key = random_string(30)
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.jinja_env.globals['categories'] = sorted(categories)
    app.jinja_env.globals['logged_in'] = is_logged_in
    params = dict(debug=True, host='localhost', port=8002)
    app.run(**params)
