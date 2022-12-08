from peewee import *
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


#--------------------------- CONNECT TO DATABASE ------------------------------#
database_products = SqliteDatabase('databases/products.db')

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

