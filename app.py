from flask import Flask, render_template, redirect, url_for, request, jsonify
from sqlalchemy.orm import sessionmaker

from models import Item, User, Like, engine, Base, categories


Base.metadata.bind = engine
dbsession = sessionmaker(bind=engine)
session = dbsession()
app = Flask(__name__)


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
def add_item():
    ''' this view will add an item to the database
        only if logged in
    '''
    pass


@app.route('/catalog/<item>/edit', methods=['POST', 'GET'])
def edit_item(item):
    ''' this view will edit an item
        only if logged in
    '''
    pass


@app.route('/catalog/<item>/delete', methods=['POST', 'GET'])
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
    pass


@app.route('/catalog.json')
def json_catalog():
    '''this view returns all items in json view'''
    pass


if __name__ == '__main__':
    params = dict(debug=True, host='localhost', port=8002)
    app.run(**params)
