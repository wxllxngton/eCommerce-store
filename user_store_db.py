from peewee import *
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


#--------------------------- CONNECT TO DATABASE ------------------------------#
database_users = SqliteDatabase('databases/user_store.db')

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

