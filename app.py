'''
simple app demonstrating CRUD
'''

from functools import wraps

from flask import (Flask, abort, render_template, redirect, url_for,
                   request, jsonify, session as web_session)
from sqlalchemy.orm import sessionmaker

from models import Item, User, Like, engine, Base, categories
from utility import random_string


Base.metadata.bind = engine
dbsession = sessionmaker(bind=engine)
session = dbsession()
app = Flask(__name__)


def is_logged_in(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'logged_in' not in web_session:
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner


@app.route('/favorites', methods=['GET', 'POST'])
def favorites():
    ''' this view will list all the favorites for a user'''
    pass


@app.route('/', methods=['GET'])
def home():
    ''' this view will list all the categories and latest item
        once you log in, you can add items
    '''
    items = session.query(Item)
    return render_template('home_page.html', items=items, categories=categories)


@app.route('/catalog/<category>/items', methods=['GET'])
def catalog_page(category):
    '''this view will show the items for a specific category '''
    pass


@app.route('/catalog/<category>/<item>', methods=['GET'])
def item_page(category, item):
    '''this view will show an item in detail
        once you log in, you can edit item
    '''
    pass


@app.route('/catalog/add', methods=['POST', 'GET'])
@is_logged_in
def add_item():
    ''' this view will add an item to the database
        only if logged in
    '''
    pass


@app.route('/catalog/<item>/edit', methods=['POST', 'GET'])
@is_logged_in
def edit_item(item):
    ''' this view will edit an item
        only if logged in
    '''
    pass


@app.route('/catalog/<item>/delete', methods=['POST', 'GET'])
@is_logged_in
def delete_item(item):
    ''' this view will delete an item
        only if logged in
    '''
    pass


@app.route('/login', methods=['POST', 'GET'])
def login():
    '''this view will login the user'''
    pass


@app.route('/logout', methods=['POST'])
def logout():
    '''this view will be used to log out the user'''
    session.pop('logged_in', None)
    return redirect(url_for('home'))


@app.route('/catalog.json')
def json_catalog():
    '''this view returns all items in json view'''
    pass


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
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    params = dict(debug=True, host='localhost', port=8002)
    app.run(**params)
