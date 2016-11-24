from flask import Flask, render_template, redirect, url_for, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Restaurant, MenuItem, User, Like, engine


Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
app = Flask(__name__)


@app.route('/', methods=['GET'])
def home():
    ''' this view will list all the restaurants in the database '''
    pass


@app.route('/favorites', methods=['GET', 'POST'])
def favorites():
    ''' this view will list all the restaurants in the database '''
    pass


@app.route('/add_restaurant', methods=['POST', 'GET'])
def add_restaurant():
    ''' this view will add a restaurant to the database '''
    pass


@app.route('/<int: restaurant_id>/edit_restaurant', methods=['POST', 'GET'])
def edit_restaurant(restaurant_id):
    ''' this view will edit a restaurant in the database '''
    pass


@app.route('/<int: restaurant_id>/add_item', methods=['POST', 'GET'])
def add_menu_item(restaurant_id):
    ''' this view will add a menu item to the database '''
    pass


@app.route('/<int: restaurant_id>/<int: menu_item_id>/edit_item', methods=['POST', 'GET'])
def edit_menu_item(restaurant_id, menu_item_id):
    ''' this view will edit a menu item in the database '''
    pass


@app.route('/<int: restaurant_id>', methods=['GET'])
def restaurant_page(restaurant_id):
    pass


@app.route('/<int: restaurant_id>/<int: item_id>', methods=['GET'])
def item_page(restaurant_id, item_id):
    pass


@app.route('/login', methods=['POST', 'GET'])
def login():
    pass


@app.route('/logout', methods=['POST'])
def logout():
    pass


@app.route('/json/')
def json_restaurants():
    '''this view returns all restaurants in json view'''
    pass


@app.route('/json/<item: restaurant_id>')
def json_items(restaurant_id):
    '''this view returns all restaurants in json view'''
    pass


if __name__ == '__main__':
    app.debug = True
    app.run(port=8002)
