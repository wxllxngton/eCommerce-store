# Import Statements
from flask import Flask, redirect, request, render_template, url_for, flash
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort
from flask_ckeditor import CKEditor, CKEditorField
import stripe

#-------------------------------- FORMS ---------------------------------------#
from forms import LoginForm
from forms import RegisterForm
from forms import AddProduct

#------------------------------------------------------------------------------#


#--------------------------- CONNECT TO DATABASE ------------------------------#
from products_db import *
from user_store_db import *
from feedback_db import *
#------------------------------------------------------------------------------#


#-------------------------------- CONFIG --------------------------------------#
# Config Flask
app = Flask(__name__)
'''Flask login
Make-shift secret key - login_manager only works in its presence'''
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'

# Config Bootstrap
Bootstrap(app)

# Config Stripe
'''This is your test secret API key.
Get your Stripe API Key here - https://stripe.com/'''
stripe.api_key = 'sk_test_51LcRknFAwMnZH9bVd5mgvKYK0nC1IpMG7bb9gUmC1b4H1v3Jh4MmY5hdFzGMDXnbJHJoHDKSc13nQkVy5sqz2J7d00v7yhA42P'

# Config ckEditor
ckeditor = CKEditor(app)

# Config LoginManager
login_manager = LoginManager()
# Confuguration
login_manager.init_app(app)

#------------------------------------------------------------------------------#


#------------------------------------ CART ------------------------------------#
items_in_cart = []
#------------------------------------------------------------------------------#


# Decorator grants admin user privilages
def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.email != 'admin@gmail.com':
            return abort(403)
        #Otherwise continue with the route function
        return function(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.get(User.id == user_id)


YOUR_DOMAIN = 'http://localhost:4242'


#----------------------------------- STRIPE -----------------------------------#
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
            success_url=YOUR_DOMAIN + '/success',
            cancel_url=YOUR_DOMAIN + '/cancel',
        )
    except Exception as e:
        return str(e)
    return redirect(checkout_session.url, code=303)

#------------------------------------------------------------------------------#


#--------------------------------- HOME PAGE ----------------------------------#
@app.route('/', methods=['GET','POST'])
def home():
    if request.method == 'POST':
        return redirect(url_for('search_by_category', category=request.form['category'].upper()))
    return render_template('index.html', products=Product.select(), items_in_cart=items_in_cart, logged_in=current_user.is_authenticated)


@app.route('/<category>', methods=['GET','POST'])
def search_by_category(category):
    products = None
    if category == 'ALL':
        products = Product.select()
    else:
        products = Product.select().where(Product.category == category)
    if request.method == 'POST':
        return redirect(url_for('search_by_category', category=request.form['category'].upper()))
    return render_template('index.html', products=products, logged_in=current_user.is_authenticated)

#------------------------------------------------------------------------------#


#------------------------------ SIGN UP PAGE ----------------------------------#
@app.route("/register", methods=['GET','POST'])
def register():
    register_form = RegisterForm()
    error = None
    if register_form.validate_on_submit():
        # Setting password
        password_hashed = generate_password_hash(password=register_form.password.data, method="pbkdf2:sha256", salt_length=8)
        # Confirming existence of email
        try:
            # Inserting data
            User.insert(email=register_form.email.data, password=password_hashed, name=register_form.name.data).execute()
            return redirect(url_for('login'))
        except IntegrityError:
            error = 'You already have an account'
            return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated, error=error)
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)

#------------------------------------------------------------------------------#



#-------------------------------- LOGIN PAGE ----------------------------------#
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

#------------------------------------------------------------------------------#



#-------------------------------- SIGN OUT ------------------------------------#
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#------------------------------------------------------------------------------#



#-------------------------------- ADD TO CART ---------------------------------#
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
            'item_price':format(float(row.price),".2f")
        }
        items_in_cart.append(item)
    return redirect(url_for('home'))

#------------------------------------------------------------------------------#


#------------------------ REMOVE FROM CART - HOME -----------------------------#
@app.route("/remove_from_cart/<index>")
def remove_from_cart(index):
    items_in_cart.pop(int(index))
    return redirect(url_for('home'))

#------------------------------------------------------------------------------#


#------------------------ REMOVE FROM CART - PTP ------------------------------#
@app.route("/remove_from_cart_page/<index>")
def remove_from_cart_page(index):
    items_in_cart.pop(int(index))
    return redirect(url_for('cart'))

#------------------------------------------------------------------------------#


#------------------------- DASHBOARD ADMIN ------------------------------------#
@app.route("/admin")
@admin_only
def admin():
    return render_template('dashboard.html')

#------------------------------------------------------------------------------#



#----------------------------- ADD ITEM TO DB ---------------------------------#
@app.route("/admin/add_item", methods=['GET', 'POST'])
def add_item():
    add_form = AddProduct()
    if add_form.validate_on_submit():
        # Inserting data
        Product.insert(img_url=add_form.img_url.data, brand=add_form.brand.data, item=add_form.item.data, description=add_form.description.data, category=add_form.category.data.upper(), price=add_form.price.data, product_id=add_form.product_id.data).execute()
        return redirect(url_for('view_items'))
    return render_template('add_item.html', form=add_form)

#------------------------------------------------------------------------------#


#----------------------------- MANAGE USERS -----------------------------------#
@app.route("/admin/users_in_db", methods=['GET', 'POST'])
def users_in_db():
    users = User.select()
    return render_template('users_in_db.html', users=users)

@app.route('/admin/users_in_db/delete-user/<int:id>')
def delete_user(id):
    if User.get(User.id == id):
        query = User.get(User.id == id)
        query.delete_instance()
    return redirect(url_for('users_in_db'))
#------------------------------------------------------------------------------#


#------------------------------ MANAGE ITEMS ----------------------------------#
@app.route("/admin/view-items", methods=['GET', 'POST'])
def view_items():
    products = Product.select()
    if request.method == 'POST':
        return redirect(url_for('search_by_category_items', category=request.form['category'].upper()))
    return render_template('items.html', products=products)


@app.route('/admin/view-items/<category>', methods=['GET','POST'])
def search_by_category_items(category):
    products = None
    if category == 'ALL':
        products = Product.select()
    else:
        products = Product.select().where(Product.category == category)
    if request.method == 'POST':
        return redirect(url_for('search_by_category_items', category=request.form['category'].upper()))
    return render_template('items.html', products=products, logged_in=current_user.is_authenticated)


@app.route('/admin/view-items/delete-item/<int:id>')
def delete_item(id):
    if Product.get(Product.id == id):
        query = Product.get(Product.id == id)
        query.delete_instance()
    return redirect(url_for('view_items'))


@app.route("/admin/view-items/edit/<int:id>", methods=['GET','POST'])
def edit_item(id):
    # Connecting To Database
    item = [product.item for product in Product.select().where(Product.id == id)][0]
    brand = [product.brand for product in Product.select().where(Product.id == id)][0]
    description = [product.description for product in Product.select().where(Product.id == id)][0]
    img_url = [product.img_url for product in Product.select().where(Product.id == id)][0]
    category = [product.category for product in Product.select().where(Product.id == id)][0].upper()
    price = [product.price for product in Product.select().where(Product.id == id)][0]
    product_id = [product.product_id for product in Product.select().where(Product.id == id)][0]

    edit_form = AddProduct(item=item, brand=brand, img_url=img_url, description=description, category=category, price=price, product_id=product_id)

    if edit_form.validate_on_submit():
        # Edit data
        q = Product.update(img_url=edit_form.img_url.data, brand=edit_form.brand.data, item=edit_form.item.data, description=edit_form.description.data, category=edit_form.category.data, price=edit_form.price.data, product_id=edit_form.product_id.data).where(Product.id == id)
        q.execute()
        return redirect(url_for('view_items'))
    return render_template("add_item.html", form=edit_form)

#------------------------------------------------------------------------------#



#------------------------------------------------------------------------------#

#------------------------------- SUCCESS --------------------------------------#
@app.route("/success", methods=['GET', 'POST'])
def success():
    return render_template('success.html')

@app.route("/cancel", methods=['GET', 'POST'])
def cancel():
    return render_template('cancel.html')

#--------------------------- MANAGE FEEDBACK ----------------------------------#
@app.route("/admin/view-feedback", methods=['GET', 'POST'])
def view_feedback():
    feedback = Feedback.select()
    return render_template('view-feedback.html', feedback=feedback)



@app.route("/post_feedback", methods=['GET'])
def post_feedback():
    # Inserting data
    Feedback.insert(fname=current_user.name, comment=request.args.get('comment')).execute()
    return redirect(url_for('home'))

#------------------------------------------------------------------------------#


if __name__ == '__main__':
    app.run(debug=True, port=4242)
