from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms import BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, InputRequired
from cadpsr.models import Colaborador, Pessoa



class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired()])
    senha = PasswordField('Senha', validators=[InputRequired()])
    remeter = SubmitField('Entrar')
