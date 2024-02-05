from flask import Flask, url_for, render_template, request, redirect, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import stripe
from flask_ckeditor import CKEditor
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import hashlib
from forms import *
from flask_migrate import Migrate

app = Flask(__name__)
ckeditor = CKEditor(app)
app.config['CKEDITOR_PKG_TYPE'] = 'standard'

SECRET_KEY = 'sk_test_51OeIHBLRdOm6Mv2pFRLgFfGYOqVeCrgHILRVokXZZda4HmeAqfUvdBIF8Ux34fcTockhK54BHdN70QmA1NkTU68B00ESwtjnB8'
PUBLISHABLE_KEY = 'pk_test_51OeIHBLRdOm6Mv2p6AfEAaY3aaEStnQnaJHXQssYHOaDxgthpgESkHSaRMI2PaoSM8uv9fNTXs8MdEpmFqvJWWIa00BJmahsd3'

stripe_keys = {'secret_key': SECRET_KEY,
               'published_key': PUBLISHABLE_KEY,
               }
stripe.api_key = stripe_keys["secret_key"]

global cart_size
cart_size = 0

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfpP1kpAAAAAHOzELguW7msMWfI4tIQQ0i0Ego-'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LfpP1kpAAAAADHMK9pcfoSv-aXqeaP9VCWf6ETl'

# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.secret_key = 'tO$&!|0wkamvVia0?n$NqIRVWOG'

#database
db = SQLAlchemy(app)

migrate = Migrate(app, db)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

bootstrap = Bootstrap5(app)

def hash_password(password):
    # Convert the password to bytes
    password_bytes = password.encode('utf-8')

    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the password bytes
    sha256.update(password_bytes)

    # Get the hexadecimal representation of the hashed password
    hashed_password = sha256.hexdigest()

    return hashed_password

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    orders = db.relationship('Order', backref='user', lazy=True)

    def get_id(self):
        return str(self.id)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_name = db.Column(db.String, nullable=False)
    price = db.Column(db.String, nullable=False)
    date = db.Column(db.String, nullable=False)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product_db.id', ondelete='CASCADE'), nullable=False)
    product_name = db.Column(db.String, nullable=False)
    price = db.Column(db.String, nullable=False)


app.config['SQLALCHEMY_BINDS'] = {
    'products_db': 'sqlite:///products.db' # The additional database
}

class ProductDB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String, nullable=False)
    product_name = db.Column(db.String, nullable=False, unique=True)
    price = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=True)
    img_url = db.Column(db.String, nullable=False)
    carts = db.relationship('Cart', backref='product_db', lazy=True)

with app.app_context():
    db.create_all()


def admin_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        # Check if the current user is authenticated and has ID equal to 1
        if not current_user.is_authenticated or current_user.id != 1:
            # Redirect or abort, depending on your requirements
            return redirect(url_for('home'))  # Redirect to login page
            # Or use abort(403) to show a forbidden error page

        # If the user is authenticated and has the required ID, proceed to the view
        return view_func(*args, **kwargs)

    return decorated_view

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    global cart_size
    all_products = ProductDB.query.all()

    # Group products by category
    grouped_products = {}
    for product in all_products:
        category = product.category
        if category not in grouped_products:
            grouped_products[category] = []
        grouped_products[category].append(product)
    try:
        cart_size = Cart.query.filter_by(user_id=current_user.id).count()
    except AttributeError:
        pass
    return render_template('home.html', grouped_products=grouped_products, cart_size=cart_size)

@app.route('/<category>/<name>/<price>')
def view_product(category, name, price):
    img_url = request.args.get('img_url')
    related_products = db.session.execute(db.select(ProductDB).filter_by(category=category)).scalars()
    description = request.args.get('description')
    return render_template('product.html', category=category, name=name, price=price, img_url=img_url, related_products=related_products, cart_size=cart_size, description=description)

@app.route('/searched-product')
def search_for_product():
    global cart_size
    search_product = request.args.get('search').lower()
    all_products = ProductDB.query.with_entities(ProductDB.product_name).all()
    all_products_list = [name[0] for name in all_products]
    wanted_products = []
    for name_product in all_products_list:
        if search_product in name_product.lower():
            product = db.session.execute(db.select(ProductDB).filter_by(product_name=name_product)).scalar_one()
            wanted_products.append(product)
    return render_template('search-product.html', product_list=wanted_products, cart_size=cart_size)

@app.route('/delete-product/<name>')
@admin_required
def delete_product(name):
    product = db.session.execute(db.select(ProductDB).filter_by(product_name=name)).scalar_one()
    product_in_cart = db.session.execute(db.select(Cart).filter_by(product_name=name)).scalars()
    for _ in product_in_cart:
        db.session.delete(_)
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('home'))

#add an item to the cart and changing the cart size
@app.route('/<name>/<price>', methods=['POST', 'GET'])
def add_to_cart(name, price):
    global cart_size
    if not current_user.is_authenticated:
        flash('You need to login to add items to cart')
        return redirect(url_for('login'))
    else:
        try:
            quantity = int(request.form.get('quantity3'))
            img_url = request.args.get('img_url')
            for _ in range(quantity):
                product = db.session.execute(db.select(ProductDB).filter_by(product_name=name)).scalar_one()
                added_item = Cart(user_id=current_user.id, product_name=name, price=price, product_id=product.id)
                db.session.add(added_item)
            db.session.commit()
            product = db.session.execute(db.select(ProductDB).filter_by(product_name=name)).scalar_one()
            cart_size = Cart.query.filter_by(user_id=current_user.id).count()
            category = request.args.get('category')
            return redirect(url_for('view_product', category=category, name=name, price=price, img_url=img_url, description=product.description))
        except:
            img_url = request.args.get('img_url')
            category = request.args.get('category')
            product = db.session.execute(db.select(ProductDB).filter_by(product_name=name)).scalar_one()
            added_item = Cart(user_id=current_user.id, product_name=name, price=price, product_id=product.id)
            db.session.add(added_item)
            db.session.commit()
            cart_size = Cart.query.filter_by(user_id=current_user.id).count()
            if request.args.get('at_home') == '1':
                return redirect(url_for('home'))
            return redirect(url_for('view_product', category=category, name=name, price=price, img_url=img_url,
                                        description=product.description))
@app.route('/thank-you')
def thank_you():
    global cart_size
    return render_template('thank-you.html', cart_size=cart_size)

@app.route('/payment', methods=['POST'])
@login_required
def payment():
    # customer Info
    cart = db.session.execute(db.select(Cart).filter_by(user_id=current_user.id)).scalars()
    rows = Cart.query.filter_by(user_id=current_user.id).all()
    total_price = sum(float(row.price[1:]) for row in rows)
    total_price = f'€{total_price:.2f}'
    customer = stripe.Customer.create(email=request.form['stripeEmail'], source=request.form['stripeToken'])

    charge = stripe.Charge.create(
        customer=customer.id,
        amount=int(float(total_price.strip('€')) * 100),
        currency='eur',
        description=''
    )

    users_cart = db.session.execute(db.select(Cart).filter_by(user_id=current_user.id)).scalars()
    for item in users_cart:
        purchased_item = Order(product_name=item.product_name, price=item.price, date=datetime.now().strftime('%d %m %Y'), user_id=current_user.id)
        db.session.add(purchased_item)
        db.session.delete(item)
    db.session.commit()

    return redirect(url_for('thank_you'))

@app.route('/view-cart', methods=['GET', 'POST'])
def view_cart():
    global cart_size
    if not current_user.is_authenticated:
        flash('You need to login to view cart')
        return redirect(url_for('login'))
    cart = db.session.execute(db.select(Cart).filter_by(user_id=current_user.id)).scalars()
    rows = Cart.query.filter_by(user_id=current_user.id).all()
    total_price = sum(float(row.price[1:]) for row in rows)
    total_price = f'€{total_price:.2f}'
    total_in_cents = int(float(total_price.strip('€')) * 100)
    return render_template('cart.html', cart_size=cart_size, cart=cart, total_price=total_price, public_key=PUBLISHABLE_KEY, total_in_cents=total_in_cents)

@app.route('/remove-from-cart/<name>')
def remove_from_cart(name):
    global cart_size
    row_to_delete = Cart.query.filter_by(product_name=name, user_id=current_user.id).first()
    db.session.delete(row_to_delete)
    db.session.commit()
    cart_size -= 1
    return redirect(url_for('view_cart'))

@app.route("/sign_in", methods=['GET', 'POST'])
def sign_in():
    sign_in_form = SignIn()
    if request.method == 'POST' and sign_in_form.validate():
        name = sign_in_form.name.data
        email = sign_in_form.email.data
        password = hash_password(sign_in_form.password.data)
        new_user = User(name=name, email=email, password=password)
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exist login instead', "error")
            return redirect(url_for('login'))
        else:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
        return redirect(url_for('home'))
    return render_template('sign_in.html', form=sign_in_form, cart_size=cart_size)

@app.route("/login", methods=['GET', 'POST'])
def login():
    login_form = LogIn()
    if request.method == 'POST' and login_form.validate():
        email = login_form.email.data
        password = hash_password(login_form.password.data)
        try:
            user = User.query.filter_by(email=email).first()
            if user.password == password:
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Incorrect Password')
                return render_template('login.html', form=login_form, cart_size=cart_size)
        except:
            flash('Incorrect Email')
            return render_template('login.html', form=login_form, cart_size=cart_size)
    return render_template('login.html', form=login_form, cart_size=cart_size)

#add a new item to the shop
@app.route('/add-new-product', methods=['GET', 'POST'])
@admin_required
def add_new_product():
    form = NewProduct()
    if form.validate_on_submit():
        category = form.category.data
        product_name = form.name.data
        price = '€' + str(round(float(form.price.data), 2))
        img_url = form.img_url.data
        description = form.description.data
        product = ProductDB(category=category, price=price, img_url=img_url, product_name=product_name, description=description)
        db.session.add(product)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('form.html', form=form, cart_size=cart_size)

@app.route('/edit-product/<name>', methods=['GET', 'POST'])
@admin_required
def edit_product(name):
    global cart_size
    product = db.session.execute(db.select(ProductDB).filter_by(product_name=name)).scalar_one()
    product_in_cart = db.session.execute(db.select(Cart).filter_by(product_name=name)).scalars()
    form = NewProduct(category=product.category,
                      name=product.product_name,
                      price=product.price.strip('€'),
                      img_url=product.img_url,
                      description=product.description)
    if form.validate_on_submit():
        product.category = form.category.data
        product.product_name = form.name.data
        product.img_url = form.img_url.data
        product.price = '€' + str(form.price.data)
        product.description = form.description.data
        for item in product_in_cart:
            item.product_name = form.name.data
            item.price = '€' + str(form.price.data)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('form.html', form=form, cart_size=cart_size)

@app.route('/purchase-history')
@login_required
def purchase_history():
    global cart_size
    purchased_item = db.session.execute(db.select(Order).filter_by(user_id=current_user.id)).scalars()
    return render_template('purchase-history.html', cart_size=cart_size, purchased_item=purchased_item)

#Log the user out of their account
@app.route('/logout', methods=['GET'])
@login_required
def logout():
    global cart_size
    if request.method == 'GET':
        logout_user()
        cart_size = 0
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)