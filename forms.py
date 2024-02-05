from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import Form, BooleanField, StringField, PasswordField, validators, SubmitField, FloatField
from wtforms.validators import DataRequired, Length
from flask_ckeditor import CKEditorField

#A signIn form
class SignIn(FlaskForm):
    name = StringField('Enter your name', validators=[DataRequired(), Length(min=0, max=40)])
    email = StringField('Email Address', [Length(min=6)])
    password = PasswordField('Password', [
        DataRequired(), Length(min=8, max=40),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    recaptcha = RecaptchaField()
    create_account = SubmitField('Create')

#Login Form
class LogIn(FlaskForm):
    email = StringField('Email Address', [Length(min=6)])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    log_in = SubmitField('login')

class NewProduct(FlaskForm):
    category = StringField('Category', validators=[DataRequired()])
    name = StringField('Product Name', validators=[DataRequired()])
    price = FloatField('Price (€)', validators=[DataRequired()])
    img_url = StringField('Image URL', validators=[DataRequired()])
    description = CKEditorField('Description')
    add_product = SubmitField('Add Product')
