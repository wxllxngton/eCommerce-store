import os
from flask import Flask, redirect, request, render_template, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from peewee import *

import stripe
# This is your test secret API key.
stripe.api_key = 'sk_test_51LcRknFAwMnZH9bVd5mgvKYK0nC1IpMG7bb9gUmC1b4H1v3Jh4MmY5hdFzGMDXnbJHJoHDKSc13nQkVy5sqz2J7d00v7yhA42P'

app = Flask(__name__)
Bootstrap(app)
# Flask login
# Make-shift secret key - login_manager only works in its presence
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'

# This is your test secret API key.
stripe.api_key = ''



login_manager = LoginManager()
# Confuguration
login_manager.init_app(app)


#------------------------------------ CART ------------------------------------#
items_in_cart = []
#------------------------------------------------------------------------------#

@login_manager.user_loader
def load_user(user_id):
    return User.get(User.id == user_id)

#--------------------------- CONNECT TO DATABASE ------------------------------#
database_users = SqliteDatabase('user_store.db')

''' Model definitions -- the standard "pattern" is to define a base model class that specifies which database to use.  then, any subclasses will automaticallyuse the correct storage'''
class BaseModel(Model):
    class Meta:
        database = database_users
# The user model specifies its fields (or columns) declaratively, like django
class User(UserMixin, BaseModel):
    id = PrimaryKeyField(unique=True, null=False)
    name = CharField()
    email = CharField()
    password = CharField()

User.create_table()


database_products = SqliteDatabase('products.db')

''' Model definitions -- the standard "pattern" is to define a base model class that specifies which database to use.  then, any subclasses will automaticallyuse the correct storage'''
class BaseModel(Model):
    class Meta:
        database = database_products
# The user model specifies its fields (or columns) declaratively, like django
class Product(BaseModel):
    id = PrimaryKeyField(unique=True, null=False)
    brand = CharField()
    category = CharField()
    img_url = CharField()
    item = CharField()
    description = CharField()
    price = CharField()
    product_id = CharField()

Product.create_table()

database_orders = SqliteDatabase('orders.db')

''' Model definitions -- the standard "pattern" is to define a base model class that specifies which database to use.  then, any subclasses will automaticallyuse the correct storage'''
class BaseModel(Model):
    class Meta:
        database = database_orders
# The user model specifies its fields (or columns) declaratively, like django
class Order(BaseModel):
    id = PrimaryKeyField(unique=True, null=False)
    brand = CharField()
    category = CharField()
    item = CharField()
    description = CharField()

Product.create_table()

#----------------------------------- FORMS ------------------------------------#
##WTForm - Login
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email(message='Input a valid email.')])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


# Register
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(message='Input a valid email.')])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign up")
#------------------------------------------------------------------------------#


YOUR_DOMAIN = 'http://localhost:4242'

@app.route('/create-checkout-session', methods=['GET','POST'])
def create_checkout_session():
    items_line = []
    for item in items_in_cart:
        new_item = {
            'price': item['item_product_id'],
            'adjustable_quantity': {'enabled': True,'minimum': 1,'maximum': 10},
            'quantity': 1,
        }
        items_line.append(new_item)
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=items_line,
            mode='payment',
            success_url=YOUR_DOMAIN + '/success.html',
            cancel_url=YOUR_DOMAIN + '/cancel.html',
        )
    except Exception as e:
        return str(e)
    return redirect(checkout_session.url, code=303)




@app.route('/')
def home():
    return render_template('index.html', products=Product.select(), items_in_cart=items_in_cart, logged_in=current_user.is_authenticated)


# Register page
@app.route("/register", methods=['GET','POST'])
def register():
    register_form = RegisterForm()
    error = None
    if register_form.validate_on_submit():
        # Setting password
        password_hashed = generate_password_hash(password=register_form.password.data, method="pbkdf2:sha256", salt_length=8)
        #Confirming existence of email
        try:
            # Inserting data
            User.insert(email=register_form.email.data, password=password_hashed, name=register_form.name.data).execute()
            return redirect(url_for('login'))
        except IntegrityError:
            error = 'You already have an account'
            return render_template("login.html", error=error)
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)


# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    error = None
    if login_form.validate_on_submit():
        # Setting parameters
        form_email = login_form.email.data
        form_password = login_form.password.data
        #Find user by email entered.
        try:
            user = User.select().where(User.email == form_email).get()
        except User.DoesNotExist:
            error = 'Email does not exist'
            return render_template("login.html", error=error)
        # Comapring data
        if check_password_hash(user.password,form_password):
            login_user(user)
            flash('You were successfully logged in')
            return redirect(url_for('home'))
        else:
            error = 'Invalid credentials'
    return render_template("login.html", form=login_form, error=error, logged_in=current_user.is_authenticated)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/cart")
def cart():
    return render_template('cart.html', items_in_cart=items_in_cart)


@app.route("/add_to_cart/<product_id>")
def add_to_cart(product_id):
    product = Product.select().where(Product.id == product_id)
    for row in product:
        item = {
            'item_product_id':row.product_id,
            'item_name':row.item,
            'item_img_url':row.img_url,
            'item_brand':row.brand,
            'item_category':row.category,
            'item_price':float(row.price.split('$')[1])
        }
        items_in_cart.append(item)
    return redirect(url_for('home'))


@app.route("/remove_from_cart/<index>")
def remove_from_cart(index):
    items_in_cart.pop(int(index))
    return redirect(url_for('home'))


@app.route("/remove_from_cart_page/<index>")
def remove_from_cart_page(index):
    items_in_cart.pop(int(index))
    return redirect(url_for('cart'))


if __name__ == '__main__':
    app.run(debug=True, port=4242)
