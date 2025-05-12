from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-for-formula'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///formula.db'  # Файл БД создастся автоматически
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модель пользователя в БД
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)  # "Листовой металл", "Трубы"
    sub_category = db.Column(db.String(50), nullable=False)  # "Лист г/к", "Трубы ВГП"
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(100))
    thickness = db.Column(db.String(20))  # Доп параметры

    

# Форма авторизации
class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

# Форма регистрации
class RegisterForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[
        DataRequired(),
        Length(min=4, max=25)
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(),
        Length(min=6)
    ])
    confirm_password = PasswordField('Подтвердите пароль', validators=[
        DataRequired(),
        EqualTo('password', message='Пароли должны совпадать!')
    ])
    submit = SubmitField('Зарегистрироваться')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Добро пожаловать в Formula!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Неверный логин или пароль!', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Это имя пользователя уже занято!', 'danger')
        else:
            new_user = User(username=form.username.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            
            login_user(new_user)
            
            flash('Регистрация успешна! Добро пожаловать.', 'success')
            return redirect(url_for('home'))
            
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/sheets')
def sheets():
    subcategories = db.session.query(
        Product.sub_category,
        Product.image
    ).filter_by(
        category="Листовой металл"
    ).distinct(Product.sub_category).all()
    
    return render_template('sheets.html', subcategories=subcategories)



from urllib.parse import unquote

@app.route('/subcategory/<path:name>')
def subcategory(name):
    decoded_name = unquote(name) 
    
    products = Product.query.filter_by(
        category="Листовой металл",
        sub_category=decoded_name
    ).all()
    
    if not products:
        return "Товары не найдены", 404
    
    return render_template('subcategory.html', 
                         products=products,
                         category_name="Листовой металл",
                         subcategory_name=decoded_name)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)