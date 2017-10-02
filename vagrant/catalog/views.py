from models import Base, User, Product, Item
from flask import Flask, jsonify, request, render_template
from flask import url_for, redirect, abort, flash
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, asc
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import random
import string


engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# fb connect starts here
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url_par1 = 'https://graph.facebook.com/oauth/access_token?gra'
    url_par2 = 'nt_type=fb_exchange_token&client_id'
    url_par3 = '=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    url = url_par1+url_par2+url_par3
    h = httplib2.Http()

    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url_par1 = 'https://graph.facebook.com/v2.8/me?access_to'
    url_par2 = 'ken=%s&fields=name,id,email' % token
    url = url_par1+url_par2
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url_par1 = 'https://graph.facebook.com/v2.8/me/picture'
    url_par2 = '?access_token=%s&redirect=0&height=200&width=200' % token
    url = url_par1+url_par2
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px'
    output += ';-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return redirect(url_for('showAllProducts'))


# disconnect Facebook login
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url_par1 = 'https://graph.facebook.com/'
    url_par2 = '%s/permissions?access_token=%s' % (facebook_id, access_token)
    url = url_par1+url_par2
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    flash("you have been logged out")
    return redirect('/')


# gconnect starts here
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
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
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
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
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        txt = 'Current user is already connected.'
        response = make_response(json.dumps(txt),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 15'
    output += '0px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        txt = 'Failed to revoke token for given user.'
        response = make_response(json.dumps(txt, 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# LOG OUT - based on provider
@app.route('/disconnect')
def disconnect():
    print login_session['provider']
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['access_token']
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['user_id']
        del login_session['provider']
        del login_session['picture']
        del login_session['email']
        del login_session['username']
        flash("You have successfully been logged out.")
        return redirect(url_for('showAllProducts'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showAllProducts'))


# backend database operations start from here
@app.route('/')
@app.route('/catalog')
def showAllProducts():
    products = session.query(Product).all()
    items = session.query(Item).all()
    if 'username' not in login_session:
        # if not logged in, render public page
        phtml = 'publicall.html'
        return render_template(phtml, products=products, items=items)
    else:
        # if logged in, render page user can edit, add and delete
        return render_template('all.html', products=products, items=items)


# ADD new category
@app.route('/catalog/new_category', methods=['GET', 'POST'])
def addCategory():
    if 'username' not in login_session:
        # login required
        return redirect('/login')
    if request.method == 'POST':
        uname = login_session['username']
        user = session.query(User).filter_by(name=uname).first()
        if request.form['name'][-5:] == '.json':
            flash("please don't use '.json' as end of category's name.")
            return redirect(url_for('addCategory'))
        for a in request.form['name']:
            if a == '/':
                flash("please don't use '/' in category's name.")
                return redirect(url_for('addCategory'))
        new_category = Product(name=request.form['name'], user_id=user.id)
        session.add(new_category)
        session.commit()
        flash('New Category %s Successfully Created' % new_category.name)
        return redirect(url_for('showAllProducts'))
    else:
        # method=='GET'
        return render_template('newCategory.html')


# ADD new item
@app.route('/catalog/new_item', methods=['GET', 'POST'])
def addItem():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        uname = login_session['username']
        user = session.query(User).filter_by(name=uname).first()
        tmp_cid = request.form['category_id']
        category = session.query(Product).filter_by(id=tmp_cid).first()
        tmpname = request.form['name']
        if tmpname[-5:] == '.json':
            flash("please don't use '.json' as end of item's name.")
            return redirect(url_for('addItem'))
        for a in tmpname:
            if a == '/':
                flash("please don't use '/' in item's name.")
                return redirect(url_for('addItem'))
        des = request.form['description']
        new_item = Item(name=tmpname, description=des, user_id=user.id)
        category.items.append(new_item)
        session.commit()
        flash('New Item %s Successfully Created' % new_item.name)
        return redirect(url_for('showAllProducts'))
    else:
        # method=='GET', render template with current categories info
        # user has to choose an existing category to push this new item
        products = session.query(Product).all()
        return render_template('newItem.html', products=products)


# EDIT category
@app.route('/catalog/<category>/edit', methods=['GET', 'POST'])
def editCategory(category):
    if 'username' not in login_session:
        # login required
        return redirect('/login')
    c = session.query(Product).filter_by(name=category).first()
    uname = login_session['username']
    user = session.query(User).filter_by(name=uname).first()
    if user.id != c.user_id:
        flash('you are not allowed to edit category other user created')
        return redirect(url_for('showAllProducts'))
    if request.method == 'POST':
        if request.form['submit'] == 'save' and request.form['name']:
            # if user actually sends request to update this cat
            if request.form['name'][-5:] == '.json':
                flash("please don't use '.json' as end of category's name.")
                return redirect(url_for('editCategory', category=category))
            for a in request.form['name']:
                if a == '/':
                    flash("please don't use '/' in category's name.")
                    return redirect(url_for('editCategory', category=category))
            c.name = request.form['name']
            session.commit()
            return redirect(url_for('showCategory', category=c.name))
        else:
            # if user cancels, redirect to previous page
            return redirect(url_for('showCategory', category=category))
    else:
        # method=='GET'
        return render_template('editCategory.html', category_name=category)


# DELETE category
@app.route('/catalog/<category>/delete', methods=['GET', 'POST'])
def deleteCategory(category):
    if 'username' not in login_session:
        # login required
        return redirect('/login')
    toDelCat = session.query(Product).filter_by(name=category).first()
    uname = login_session['username']
    user = session.query(User).filter_by(name=uname).first()
    if user.id != toDelCat.user_id:
        flash('you are not allowed to delete category other user created')
        return redirect(url_for('showAllProducts'))
    if request.method == 'POST':
        if request.form['submit'] == 'save':
            # if user actually sends request to delete cat
            if toDelCat:
                session.delete(toDelCat)
            flash('%s and belonged items Successfully Deleted' % category)
            session.commit()
            return redirect(url_for('showAllProducts'))
        else:
            # if user cancels, redirect
            return redirect(url_for('showCategory', category=category))
    else:
        # method=='GET'
        return render_template('deleteCategory.html', category_name=category)


@app.route('/catelog/<category>/<item>')
def showItem(category, item):
    i = session.query(Item).filter_by(name=item).first()
    if i is None or i.category.name != category:
        flash('No such item under category')
        return redirect(url_for('showAllProducts'))
    else:
        if 'username' not in login_session:
            # if not logged in, render public page
            return render_template('publicitem.html', item=i)
        else:
            # if logged in, user can update or delete item
            return render_template('item.html', category_name=category, item=i)


# SHOW category's items
@app.route('/catalog/<category>/items')
def showCategory(category):
    c = session.query(Product).filter_by(name=category).first()
    items = session.query(Item).filter_by(category_id=c.id).all()
    if 'username' not in login_session:
        # if not log in, user can only see category's items
        phtml = 'publiccategory.html'
        return render_template(phtml, category_name=category, items=items)
    else:
        # if login, user can edit category, add items, delete category
        h = 'category.html'
        return render_template(h, category_name=category, items=items)


@app.route('/catalog/<category>/<item>/edit', methods=['GET', 'POST'])
def editItem(category, item):
    if 'username' not in login_session:
        # login required
        return redirect('/login')
    EI = session.query(Item).filter_by(name=item).first()
    ps = session.query(Product).all()
    if ps is None:
        flash("you haven't created any category yet.")
        return redirect(url_for('addCategory'))
    if EI is None or EI.category.name != category:
        flash('This item is not under the category you select')
        return redirect(url_for('showAllProducts'))
    uname = login_session['username']
    user = session.query(User).filter_by(name=uname).first()
    if user.id != EI.user_id:
        flash('you are not allowed to edit items other user created')
        return redirect(url_for('showAllProducts'))
    if request.method == 'POST':
        if request.form['submit'] == 'save':
            # if user actually sends request to update
            if request.form['name']:
                # update name
                if request.form['name'][-5:] == '.json':
                    flash("please don't use '.json' as end of item's name.")
                    h = 'editItem'
                    return redirect(url_for(h, category=category, item=item))
                for a in request.form['name']:
                    if a == '/':
                        flash("please don't use '/' in item's name.")
                        h, c, i = 'editCategory', category, item
                        return redirect(url_for(h, category=c, item=i))
                EI.name = request.form['name']
            if request.form['description']:
                # update description
                EI.description = request.form['description']
            r_c_id = request.form['category_id']
            if r_c_id and r_c_id != EI.category.id:
                # if update belonged cat
                # need to redirect to new url with new cat name
                c = session.query(Product).filter_by(id=r_c_id).first()
                if c:
                    EI.category = c
            session.commit()
            cn = EI.category.name
            return redirect(url_for('showItem', category=cn, item=EI.name))
        else:
            # if user cancels
            c, i = category, item
            return redirect(url_for('showItem', category=c, item=i))
    else:
        # method=='GET'
        return render_template('editItem.html', item=EI, products=ps)


# DELETE AN ITEM
@app.route('/catalog/<category>/<item>/delete', methods=['GET', 'POST'])
def deleteItem(category, item):
    if 'username' not in login_session:
        # login required
        return redirect('/login')
    c = session.query(Product).filter_by(name=category).first()
    if c is None:
        flash("you haven't created this category yet.")
        return redirect(url_for('addCategory'))
    toDelItem = session.query(Item).filter_by(name=item).first()
    if toDelItem is None or toDelItem.category.name != category:
        flash("item not valid, or not under this category")
        return redirect(url_for('showAllProducts'))
    uname = login_session['username']
    user = session.query(User).filter_by(name=uname).first()
    if user.id != toDelItem.user_id:
        flash('you are not allowed to delete item other user created')
        return redirect(url_for('showAllProducts'))
    if request.method == 'POST':
        if request.form['submit'] == 'save':
            session.delete(toDelItem)
            session.commit()
        return redirect(url_for('showCategory', category=category))
    else:
        # method=='GET'
        return render_template('deleteItem.html', item_name=item)


# JSON Endpoint
@app.route('/catalog.json')
def catalogJSON():
    cs = session.query(Product).all()
    items = session.query(Item).all()
    if cs is None:
        flash('Nothing available. you have created anything yet.')
        return redirect(url_for('showAllProducts'))
    elif items is None:
        return jsonify(Category=[c.serialize for c in cs])
    c_sl = [c.serialize for c in cs]
    i_sl = [i.serialize for i in items]
    return jsonify(Category=c_sl, Item=i_sl)


@app.route('/catalog/<category>.json')
def categoryJSON(category):
    c = session.query(Product).filter_by(name=category).first()
    if c is None:
        flash('This category is not valid')
        return redirect(url_for('showAllProducts'))
    return jsonify(c.serialize)


@app.route('/catalog/<category>/<item>.json')
def itemJSON(category, item):
    c = session.query(Product).filter_by(name=category).first()
    if c is None:
        flash('This category is not valid')
        return redirect(url_for('showAllProducts'))
    i = session.query(Item).filter_by(name=item).first()
    if i is None or i.category.id != c.id:
        flash('This item is not valid or not under the category you select')
        return redirect(url_for('showAllProducts'))
    return jsonify(i.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
