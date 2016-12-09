'''
simple app demonstrating CRUD
'''

import json
from functools import wraps

import requests
from flask import (Flask, abort, flash, render_template,
                   redirect, url_for, request, jsonify,
                   make_response, session as web_session)
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from sqlalchemy.orm import sessionmaker
from sqlalchemy import or_

from models import Item, User, Like, engine, Base, categories
from utility import random_string


app = Flask(__name__)


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


def is_logged_in():
    ''' check if a user is logged in
        can be used to decide whether to
        display certain features on front-end
    '''
    return 'logged_in' in web_session


@app.before_request
def check_state_token(*args, **kwargs):
    ''' check a post request for a state token, protects against csrf attack '''
    if request.method == 'POST':
        connect_methods = ['/gconnect', '/fbconnect', '/ghconnect']
        if request.path in connect_methods:
            data = request.data.decode('utf-8') 
            page_state = json.loads(data)['state']  
        else:
            page_state = request.form.get('state')
        state = web_session.get('state', None)
        print('state = %s' % state)
        print('page_state = %s' % page_state)
        if not state or page_state != state:
            print('forbidden')
            abort(403)


def generate_state_token():
    ''' generate a random state token,
        to be used for every post request
    '''
    if 'state' not in web_session:
        web_session['state'] = random_string()
        print(web_session['state'])
    return web_session['state']


@app.route('/')
def home():
    ''' this view will list all the categories and latest item
        once you log in, you can add items
    '''
    latest = session.query(Item).order_by(Item.date_added.desc())[:5]
    return render_template('home_page.html', latest=latest)


@app.route('/catalog/<category>/items')
def category_page(category):
    '''this view will show the items for a specific category '''
    if category not in categories:
        return render_template('no_such.html', _object='category'), 400
    items = session.query(Item).filter_by(category=category).order_by(Item.title)
    return render_template('category_page.html', category=category, items=items)


@app.route('/catalog/<category>/<title>/<int:item_id>')
def item_page(category, title, item_id):
    '''this view will show an item in detail
        once you log in, you can edit item
    '''
    # TODO: what to do if multiple items have same name & same category
    # item = session.query(Item).filter_by(category=category, title=title).first()
    item = session.query(Item).get(item_id)
    if not item:
        flash('no such item')
        return render_template('no_such.html', _object='item'), 400
    editable = item.user_email == web_session.get('email', '')
    favorited = session.query(Like).filter_by(
        item=item, user_email=web_session.get('email', '')).first()
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
        return render_template('item_form.html', url=request.path, header='Add an item')
    category = request.form.get('category', '')
    description = request.form.get('description', '').strip()
    title = request.form.get('title', '').strip()
    picture = request.form.get('picture', '').strip()
    if not (category and title and description) or category not in categories:
        flash('add failed')
        return redirect(url_for('home'))
    item = Item(title=title, description=description,
                category=category, user_email=web_session['email'],
                picture=picture)
    session.add(item)
    session.commit()
    return redirect(url_for('home'))


@app.route('/catalog/<title>/edit/<int:item_id>', methods=['POST', 'GET'])
@confirm_login
def edit_item(title, item_id):
    ''' this view will edit an item
        only if logged in
        only if you added the item
    '''
    # item = session.query(Item).filter_by(title=title).first()
    item = session.query(Item).get(item_id)
    if not item:
        flash('no such item')
        return render_template('no_such.html', _object='item'), 400
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
    new_picture = request.form.get('picture', '').strip()
    if not (category and new_title and description) or category not in categories:
        flash('edit failed')
        return redirect(url_for('home'))
    item.title = new_title
    item.category = category
    item.description = description
    item.picture = new_picture
    session.add(item)
    session.commit()
    flash('edit successful')
    return redirect(url_for('home'))


@app.route('/catalog/<title>/delete/<int:item_id>', methods=['POST'])
@confirm_login
def delete_item(title, item_id):
    ''' this view will delete an item
        only if logged in
        only if you added the item
    '''
    # item = session.query(Item).filter_by(title=title).first()
    item = session.query(Item).get(item_id)
    if not item:
        flash('no such item')
        return redirect(url_for('home'))
    if item.user_email != web_session['email']:
        flash('you can only delete your own items')
        return redirect(url_for('home'))
    # before deleting, delete all likes attributed with this item
    likes = session.query(Like).filter_by(item=item).all()
    print(likes)
    [session.delete(l) for l in likes]
    session.delete(item)
    session.commit()
    likes = session.query(Like).filter_by(item=item).all()
    print(likes)
    flash('item successfully deleted')
    return redirect(url_for('home'))


@app.route('/login')
def login():
    '''this view will login the user'''
    if request.method == 'GET':
        return render_template('login.html')


def gdisconnect():
    ''' Revoke a current user's token and reset their web_session '''

    access_token = web_session['access_token']
    if access_token is None:
        return redirect(url_for('home'))
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    result = requests.get(url)
    if result.status_code == '200':
        web_session.pop('access_token', None)
        web_session.pop('gplus_id', None)
        web_session.pop('username', None)
        web_session.pop('email', None)
        web_session.pop('picture', None)
        return True
    else:
        return False


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    ''' connect to facebook via oauth api '''
    # access_token = request.data
    data = request.data.decode('utf-8') 
    access_token = json.loads(data)['access_token']
    print(access_token)
    with open('fb_client_secrets.json', 'r') as f:
        client_secret = json.loads(f.read())
    app_id = client_secret['web']['app_id']
    app_secret = client_secret['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s'
    url = url % (app_id, app_secret, access_token)
    result = requests.get(url).text
    print(result)
    # strip expire tag from access token
    token = result.split("&")[0]
    access_token = token.split("=")[1]
    # Use token to get user info from API
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    data = requests.get(url).json()
    name, email = data['name'], data['email']
    web_session['facebook_id'] = data["id"]
    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    data = requests.get(url).json()
    picture = data["data"]["url"]
    web_session['access_token'] = access_token
    web_session['username'], web_session['picture'], web_session['email'] = name, picture, email
    web_session['logged_in'], web_session['oauth_provider'] = True, 'facebook'
    # see if user exists
    user = session.query(User).get(email)
    if not user:
        user = User(email=email, name=name, picture=picture)
        session.add(user)
    else:
        user.name = name
        user.email = email
        user.picture = picture
    session.commit()
    flash("Now logged in as %s" % name)
    return name


def fbdisconnect():
    ''' logout of facebook sign in'''
    facebook_id = web_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = web_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    requests.delete(url)
    web_session.pop('access_token', None)
    web_session.pop('facebook_id', None)
    web_session.pop('username', None)
    web_session.pop('email', None)
    web_session.pop('picture', None)
    return True


@app.route('/gconnect', methods=['POST'])
def gconnect():
    ''' login via google oauth api '''
    # code = request.data
    data = request.data.decode('utf-8') 
    code = json.loads(data)['code']
    print(code)
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('google_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    result = requests.get(url).json()
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
    with open('google_client_secrets.json', 'r') as f:
        client_secret = json.loads(f.read())
    client_id = client_secret['web']['client_id']
    if result['issued_to'] != client_id:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = web_session.get('access_token')
    stored_gplus_id = web_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    web_session['access_token'] = credentials.access_token
    web_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    data = requests.get(userinfo_url, params=params).json()
    name, email, picture = data['name'], data['email'], data['picture']
    web_session['username'], web_session['picture'], web_session['email'] = name, picture, email
    web_session['logged_in'], web_session['oauth_provider'] = True, 'google'
    user = session.query(User).get(email)
    if not user:
        user = User(email=email, name=name, picture=picture)
        session.add(user)
        session.commit()
    flash("you are now logged in as {0}".format(name))
    return name


@app.route('/logout')
def logout():
    '''this view will be used to log out the user'''
    web_session.pop('logged_in', None)
    oauth_provider = web_session.pop('oauth_provider', None)
    if oauth_provider:
        if 'google' in oauth_provider:
            gdisconnect()
        elif 'facebook' in oauth_provider:
            fbdisconnect()
        elif 'github' in oauth_provider:
            ghdisconnect()
    return redirect(url_for('home'))


@app.route('/catalog.json')
def json_catalog():
    '''this view returns all items in json view'''
    items = session.query(Item)
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<category>/items.json')
def json_category(category):
    '''this view returns all items of a category in json view'''
    items = session.query(Item).filter_by(category=category)
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<category>/<title>/item.json')
def json_item(category, title):
    '''this view returns an item description in json view'''
    item = session.query(Item).filter_by(
        category=category, title=title).first()
    if not item:
        flash('no such item')
        return jsonify(item=None)
    return jsonify(item=item.serialize)


@app.route('/profile')
@confirm_login
def profile():
    ''' this view will list all the favorites for a user'''
    user = session.query(User).get(web_session['email'])
    favorites = [l.item for l in session.query(Like).filter_by(user=user)]
    print(favorites)
    items = session.query(Item).filter_by(user=user)
    return render_template('profile.html', favorites=favorites, items=items, **user.serialize)


@app.route('/catalog/favorite/<title>/<int:item_id>', methods=['POST'])
@confirm_login
def favorite(title, item_id):
    ''' this view will list all the favorites for a user'''

    user = session.query(User).get(web_session['email'])
    print(title)
    # item = session.query(Item).filter_by(title=title).first()
    item = session.query(Item).get(item_id)
    if not item or item.user == user:
        return jsonify(favorite='fail')
    old_like = session.query(Like).filter_by(user=user, item=item).first()
    if old_like:
        session.delete(old_like)
        session.commit()
        return jsonify(favorite='successful', like='unliked')
    else:
        like = Like(user=user, item=item)
        session.add(like)
        session.commit()
        return jsonify(favorite='successful', like='liked')


@app.route('/search')
def search():
    ''' this view returns the results of a search query from front end '''
    term = request.args.get('search')
    items = session.query(Item).filter(or_(
        Item.category.like('%{0}%'.format(term)),
        Item.title.like('%{0}%'.format(term))))
    return render_template('search.html', term=term, items=items)


@app.errorhandler(404)
def page_not_found(e):
    ''' default 404 page '''
    return render_template('no_such.html', _object='Page'), 404


if __name__ == '__main__':
    Base.metadata.bind = engine
    dbsession = sessionmaker(bind=engine)
    session = dbsession()
    app.secret_key = random_string(30)
    app.jinja_env.globals['categories'] = sorted(categories)
    app.jinja_env.globals['logged_in'] = is_logged_in
    app.jinja_env.globals['state'] = generate_state_token
    params = dict(debug=True, host='localhost', port=8002)
    app.run(**params)
