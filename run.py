'''
simple app demonstrating CRUD
'''

import json
import logging
from functools import wraps
from os.path import join, dirname

import requests
from flask import (Flask, abort, flash, jsonify, make_response,
                   redirect, render_template, request,
                   session, url_for)
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from sqlalchemy.orm import sessionmaker
from sqlalchemy import or_

from models import Base, Item, Like, User, categories, engine
from utility import random_string


def generate_state_token():
    ''' generate a random state token,
        to be used for every post request
    '''
    if 'state' not in session:
        session['state'] = random_string()
    return session['state']


def is_logged_in():
    ''' check if a user is logged in
        can be used to decide whether to
        display certain features on front-end
    '''
    return 'logged_in' in session


app = Flask(__name__)
Base.metadata.bind = engine
dbsession = sessionmaker(bind=engine)
dbsession = dbsession()
app.jinja_env.globals['categories'] = sorted(categories)
app.jinja_env.globals['logged_in'] = is_logged_in
app.jinja_env.globals['state'] = generate_state_token
config_file = join(dirname(__file__), 'config.json')
with open(config_file) as f:
    config = json.load(f)
app.config['GOOGLE_OAUTH'] = config['oauth']['google']
app.config['FACEBOOK_OAUTH'] = config['oauth']['facebook']
log = config['log']


def confirm_login(func):
    ''' confirm a user is logged in
        to be used as a decorator for adding/editing/deleting
    '''
    @wraps(func)
    def inner(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner


@app.before_request
def check_state_token():
    '''
    check a post request for a state token,
    protects against csrf attack
    '''
    if request.method == 'POST':
        connect_methods = ['/gconnect', '/fbconnect']
        if request.path in connect_methods:
            data = request.data.decode('utf-8')
            page_state = json.loads(data)['state']
        else:
            page_state = request.form.get('state')
        state = session.pop('state', None)
        if not state or page_state != state:
            abort(403)


@app.route('/')
def home():
    ''' this view will list all the categories and latest item
        once you log in, you can add items
    '''
    latest = dbsession.query(Item).order_by(Item.date_added.desc())[:5]
    return render_template('home_page.html', latest=latest)


@app.route('/catalog/<category>/items')
def category_page(category):
    '''this view will show the items for a specific category '''
    if category not in categories:
        return render_template('no_such.html', _object='category'), 400
    items = dbsession.query(Item).filter_by(
        category=category).order_by(Item.title)
    return render_template(
        'category_page.html',
        category=category,
        items=items)


@app.route('/catalog/<category>/<title>/<int:item_id>')
def item_page(category, title, item_id):
    '''this view will show an item in detail
        once you log in, you can edit item
    '''
    item = dbsession.query(Item).get(item_id)
    if not item:
        flash('no such item')
        return render_template('no_such.html', _object='item'), 400
    editable = item.user_email == session.get('email', '')
    favorited = dbsession.query(Like).filter_by(
        item=item, user_email=session.get('email', '')).first()
    return render_template('item_page.html',
                           favorited=favorited,
                           editable=editable,
                           **item.serialize)


@app.route('/catalog/add', methods=['POST', 'GET'])
@confirm_login
def add_item():
    ''' this view will add an item to the database
        only if logged in
    '''
    if request.method == 'GET':
        return render_template(
            'item_form.html',
            url=request.path,
            header='Add an item')
    category = request.form.get('category', '')
    description = request.form.get('description', '').strip()
    title = request.form.get('title', '').strip()
    picture = request.form.get('picture', '').strip()
    if not (category and title and description) or category not in categories:
        flash('add failed')
        return redirect(url_for('home'))
    item = Item(title=title, description=description,
                category=category, user_email=session['email'],
                picture=picture)
    dbsession.add(item)
    dbsession.commit()
    return redirect(url_for('home'))


@app.route('/catalog/<title>/edit/<int:item_id>', methods=['POST', 'GET'])
@confirm_login
def edit_item(title, item_id):
    ''' this view will edit an item
        only if logged in
        only if you added the item
    '''
    # item = dbsession.query(Item).filter_by(title=title).first()
    item = dbsession.query(Item).get(item_id)
    if not item:
        flash('no such item')
        return render_template('no_such.html', _object='item'), 400
    if item.user_email != session['email']:
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
    new_picture = request.form.get('picture', '').strip()
    if not (
        category and new_title and description) or (
            category not in categories):
        flash('edit failed')
        return redirect(url_for('home'))
    item.title = new_title
    item.category = category
    item.description = description
    item.picture = new_picture
    dbsession.add(item)
    dbsession.commit()
    flash('edit successful')
    return redirect(url_for('home'))


@app.route('/catalog/<title>/delete/<int:item_id>', methods=['POST'])
@confirm_login
def delete_item(title, item_id):
    ''' this view will delete an item
        only if logged in
        only if you added the item
    '''
    # item = dbsession.query(Item).filter_by(title=title).first()
    item = dbsession.query(Item).get(item_id)
    if not item:
        flash('no such item')
        return redirect(url_for('home'))
    if item.user_email != session['email']:
        flash('you can only delete your own items')
        return redirect(url_for('home'))
    # before deleting, delete all likes attributed with this item
    likes = dbsession.query(Like).filter_by(item=item).all()
    [dbsession.delete(l) for l in likes]
    dbsession.delete(item)
    dbsession.commit()
    likes = dbsession.query(Like).filter_by(item=item).all()
    flash('item successfully deleted')
    return redirect(url_for('home'))


@app.route('/login')
def login():
    '''this view will login the user'''
    if is_logged_in():
        flash('you are already logged in silly')
        return redirect(url_for('home'))
    return render_template('login.html')


def gdisconnect():
    ''' Revoke a current user's token and reset their session '''

    access_token = session['access_token']
    if access_token is None:
        return redirect(url_for('home'))
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    result = requests.get(url)
    if result.status_code == '200':
        session.pop('access_token', None)
        session.pop('id', None)
        session.pop('username', None)
        session.pop('email', None)
        session.pop('picture', None)
        return True
    else:
        return False


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    ''' connect to facebook via oauth api '''
    # access_token = request.data
    logging.info("logging into facebook")
    api = 'https://graph.facebook.com'
    data = request.data.decode('utf-8')
    exchange_token = json.loads(data)['access_token']
    client_secret_file = app.config['FACEBOOK_OAUTH']
    with open(client_secret_file, 'r') as f:
        client_secret = json.loads(f.read())
    app_id = client_secret['web']['app_id']
    app_secret = client_secret['web']['app_secret']
    exchange_tokens_url = join(api, 'oauth/access_token')
    exchange_tokens_params = dict(
        grant_type='fb_exchange_token',
        client_id=app_id,
        client_secret=app_secret,
        fb_exchange_token=exchange_token)
    token_exchange_response = requests.get(
            exchange_tokens_url,
            exchange_tokens_params)
    if token_exchange_response.status_code != 200:
        err_response = make_response(
            json.dumps("Could not exchange access token"), 401)
        err_response.headers['Content-Type'] = 'application/json'
        return err_response
    access_token = token_exchange_response.json()['access_token']
    # Use token to get user info from API
    user_info_url = join(api, 'v2.12/me')
    user_info_params = dict(
        access_token=access_token,
        fields='name,id,email')
    user_info_response = requests.get(user_info_url, user_info_params)
    if user_info_response.status_code != 200:
        err_response = make_response(
            json.dumps("Could not reach user info api"), 401)
        err_response.headers['Content-Type'] = 'application/json'
        return err_response
    user_data = user_info_response.json()
    # Get user picture
    picture_url = join(api, 'v2.12/me/picture')
    picture_params = dict(
        access_token=access_token,
        redirect=0,
        height=200,
        width=200)
    picture_response = requests.get(picture_url, picture_params)
    if picture_response.status_code != 200:
        err_response = make_response(
            json.dumps("Could not reach Picture info api"), 401)
        err_response.headers['Content-Type'] = 'application/json'
        return err_response
    picture_data = picture_response.json()

    name = session['username'] = user_data['name']
    email = session['email'] = user_data['email']
    picture = session['picture'] = picture_data["data"]["url"]
    session['id'] = user_data["id"]
    session['logged_in'] = True
    session['oauth_provider'] = 'facebook'
    session['access_token'] = access_token
    # see if user exists
    user = dbsession.query(User).get(email)
    if not user:
        user = User(email=email, name=name, picture=picture)
        dbsession.add(user)
    else:
        user.name = name
        user.email = email
        user.picture = picture
    dbsession.commit()
    flash("Now logged in as %s" % name)
    return name


def fbdisconnect():
    ''' logout of facebook '''
    facebook_id = session['id']
    # The access token must be included to successfully logout
    access_token = session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
            facebook_id, access_token)
    requests.delete(url)
    session.pop('access_token', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('email', None)
    session.pop('picture', None)
    return True


@app.route('/gconnect', methods=['POST'])
def gconnect():
    ''' login via google oauth api '''
    # code = request.data
    logging.info("connecting to google")
    api = 'https://www.googleapis.com/oauth2/v1/'
    data = request.data.decode('utf-8')
    code = json.loads(data)['code']
    client_secret_file = app.config['GOOGLE_OAUTH']
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(client_secret_file, scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    verify_token_url = join(api, 'tokeninfo?access_token=%s' % access_token)
    result = requests.get(verify_token_url).json()
    # If there was an error in the access token info, abort.
    if result.get('error'):
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    with open(client_secret_file) as f:
        client_secret = json.loads(f.read())
    client_id = client_secret['web']['client_id']
    if result['issued_to'] != client_id:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = session.get('access_token')
    stored_gplus_id = session.get('id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    user_info_url = join(api, "userinfo")
    params = {'access_token': access_token, 'alt': 'json'}
    user_data_response = requests.get(user_info_url, params=params)
    user_data = user_data_response.json()
    name = session['username'] = user_data['name']
    picture = session['picture'] = user_data['picture']
    email = session['email'] = user_data['email']
    session['logged_in'] = True
    session['oauth_provider'] = 'google'
    session['access_token'] = access_token
    session['id'] = gplus_id
    user = dbsession.query(User).get(email)
    if not user:
        user = User(email=email, name=name, picture=picture)
        dbsession.add(user)
        dbsession.commit()
    flash("Now logged in as %s" % name)
    return name


@app.route('/logout')
def logout():
    '''this view will be used to log out the user'''
    session.pop('logged_in', None)
    oauth_provider = session.pop('oauth_provider', None)
    if oauth_provider:
        if 'google' in oauth_provider:
            gdisconnect()
        elif 'facebook' in oauth_provider:
            fbdisconnect()
    return redirect(url_for('home'))


@app.route('/catalog.json')
def json_catalog():
    '''this view returns all items in json view'''
    items = dbsession.query(Item)
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<category>/items.json')
def json_category(category):
    '''this view returns all items of a category in json view'''
    items = dbsession.query(Item).filter_by(category=category)
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<category>/<title>/<int:item_id>/item.json')
def json_item(category, title, item_id):
    '''this view returns an item description in json view'''
    item = dbsession.query(Item).get(item_id)
    if not item:
        return jsonify(item=None)
    return jsonify(item=item.serialize)


@app.route('/profile')
@confirm_login
def profile():
    ''' this view will list all the favorites for a user'''
    user = dbsession.query(User).get(session['email'])
    favorites = [l.item for l in dbsession.query(Like).filter_by(user=user)]
    items = dbsession.query(Item).filter_by(user=user)
    return render_template(
        'profile.html',
        favorites=favorites,
        items=items,
        **user.serialize)


@app.route('/catalog/favorite/<title>/<int:item_id>', methods=['POST'])
@confirm_login
def favorite(title, item_id):
    ''' this view will list all the favorites for a user'''

    user = dbsession.query(User).get(session['email'])
    # item = dbsession.query(Item).filter_by(title=title).first()
    item = dbsession.query(Item).get(item_id)
    state = generate_state_token()
    if not item or item.user == user:
        return jsonify(favorite='fail', state=state)
    old_like = dbsession.query(Like).filter_by(user=user, item=item).first()
    if old_like:
        dbsession.delete(old_like)
        dbsession.commit()
        return jsonify(favorite='successful', like='unliked', state=state)
    else:
        like = Like(user=user, item=item)
        dbsession.add(like)
        dbsession.commit()
        return jsonify(favorite='successful', like='liked', state=state)


@app.route('/search')
def search():
    ''' this view returns the results of a search query from front end '''
    term = request.args.get('search')
    items = dbsession.query(Item).filter(or_(
        Item.category.like('%{0}%'.format(term)),
        Item.title.like('%{0}%'.format(term))))
    return render_template('search.html', term=term, items=items)


@app.errorhandler(404)
def page_not_found(e):
    ''' default 404 page '''
    return render_template('no_such.html', _object='Page'), 404


if __name__ == '__main__':
    app.secret_key = random_string(30)
    logging.basicConfig(filename=log, level=logging.DEBUG)
    params = config['app']
    app.run(**params)
