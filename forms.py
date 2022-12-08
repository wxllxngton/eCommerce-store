# Import Statements
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email
from flask_ckeditor import CKEditor, CKEditorField
from flask import Flask
from flask_wtf import FlaskForm


app = Flask(__name__)
# Flask login
# Make-shift secret key - login_manager only works in its presence
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
ckeditor = CKEditor(app)

#----------------------------------- FORMS ------------------------------------#
##WTForm - Login
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email(message='Input a valid email.')])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign up")


# Register
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(message='Input a valid email.')])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

# AddProduct
class AddProduct(FlaskForm):
    img_url = StringField("Img URL", validators=[DataRequired()])
    brand = StringField("Brand", validators=[DataRequired()])
    category = StringField("Category", validators=[DataRequired()])
    item = StringField("Item", validators=[DataRequired()])
    price = StringField("Price", validators=[DataRequired()])
    product_id = StringField("Product ID", validators=[DataRequired()])
    description = CKEditorField("Description", validators=[DataRequired()])
    submit = SubmitField("Submit")

