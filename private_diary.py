from flask import Flask, request, render_template, redirect, session
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, PasswordField, BooleanField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'


class AddNewsForm(FlaskForm):
    title = StringField('Заголовок новости', validators=[DataRequired()])
    content = TextAreaField('Текст новости', validators=[DataRequired()])
    submit = SubmitField('Добавить')


class DB:
    def __init__(self):
        conn = sqlite3.connect("sqlite/databases/mydb1.db", check_same_thread=False)
        self.conn = conn

    def get_connection(self):
        return self.conn

    def __del__(self):
        self.conn.close()


class UsersModel:
    def __init__(self, connection):
        self.connection = connection

    def init_table(self):
        cursor = self.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             user_name VARCHAR(50),
                             password_hash VARCHAR(128)
                             )''')
        cursor.close()
        self.connection.commit()

    def insert(self, user_name, password_hash):
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO users 
                          (user_name, password_hash) 
                          VALUES (?,?)''', (user_name, password_hash))
        cursor.close()
        self.connection.commit()

    def get(self, user_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (str(user_id),))
        row = cursor.fetchone()
        return row

    def get_all(self):
        cursor = self.connection.cursor()
        cursor.execute('''select *, (select count(*) from news where news.user_id = users.id) as qty from users''')
        rows = cursor.fetchall()
        return rows

    def exists(self, user_name, password_hash):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE user_name = ? AND password_hash = ?",
                       (user_name, password_hash))
        row = cursor.fetchone()
        return (True, row[0]) if row else (False,)


class NewsModel:
    def __init__(self, connection):
        self.connection = connection

    def init_table(self):
        cursor = self.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS news 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             title VARCHAR(100),
                             content VARCHAR(1000),
                             user_id INTEGER
                             )''')
        cursor.close()
        self.connection.commit()

    def insert(self, title, content, user_id):
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO news 
                          (title, content, user_id) 
                          VALUES (?,?,?)''', (title, content, str(user_id)))
        cursor.close()
        self.connection.commit()

    def get(self, news_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM news WHERE id = ?", (str(news_id),))
        row = cursor.fetchone()
        return row

    def get_all(self, user_id=None):
        cursor = self.connection.cursor()
        if user_id:
            try:
                cursor.execute("SELECT * FROM news WHERE user_id = ? ORDER BY id {}".format(session['srt']),
                               (str(user_id),))
            except Exception:
                cursor.execute("SELECT * FROM news WHERE user_id = ?",
                               (str(user_id),))
        else:
            try:
                cursor.execute("SELECT * FROM news WHERE user_id = ? ORDER BY id {}".format(session['srt']),
                               (str(user_id),))
            except Exception:
                cursor.execute("SELECT * FROM news WHERE user_id = ?",
                               (str(user_id),))
        rows = cursor.fetchall()
        return rows

    def delete(self, news_id):
        cursor = self.connection.cursor()
        cursor.execute('''DELETE FROM news WHERE id = ?''', (str(news_id),))
        cursor.close()
        self.connection.commit()


db = DB()
user_model = UsersModel(db.get_connection())


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = LoginForm()

    if request.method == 'GET':
        session['username'] = ''
        if form.validate_on_submit():
            return redirect('/success')
        return render_template('index.html', title='Регистация', form=form)

    if request.method == 'POST':
        user_name = form.username.data
        if user_name != 'Admin':
            password = form.password.data
            exists = user_model.exists(user_name, password)
            if not exists[0]:
                session['username'] = user_name
                user_model.insert(user_name, password)
                exists = user_model.exists(user_name, password)
                if exists[0]:
                    session['username'] = user_name
                    session['user_id'] = exists[1]
            else:
                return redirect('/registration')

            return redirect("/main")
        else:
            return redirect('/registration')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'GET':
        if form.validate_on_submit():
            return redirect('/success')
        return render_template('index.html', title='Авторизация', form=form)

    if request.method == 'POST':
        user_name = form.username.data
        password = form.password.data
        exists = user_model.exists(user_name, password)
        if exists[0]:
            session['username'] = user_name
            session['user_id'] = exists[1]
        return redirect("/main")


@app.route('/logout')
def logout():
    session.pop('username', 0)
    session.pop('user_id', 0)
    return redirect('/login')


@app.route('/')
@app.route('/main')
def main():

    if request.method == 'GET':

        if 'username' not in session:
            return redirect('/login')

        if 'p' in request.values.keys() and request.values['p']:
            try:
                if not session['srt']:
                    session['srt'] = 'desc'
                else:
                    session['srt'] = ''
            except Exception:
                session['srt'] = 'desc'

        try:
            news = NewsModel(db.get_connection()).get_all(user_id=session['user_id'])
        except KeyError:
            return redirect('/login')

        return render_template('main.html', username=session['username'], news=news) if session['username'] != 'Admin' \
            else render_template('main_admin.html', username=session['username'], news=news)

    if request.method == 'POST':
        pass


@app.route('/super_page', methods=['GET', 'POST'])
def super_page():
    users = user_model.get_all()
    return render_template('super_page.html', username=session['username'], users=users)


@app.route('/add_news', methods=['GET', 'POST'])
def add_news():
    if 'username' not in session:
        return redirect('/login')
    form = AddNewsForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        nm = NewsModel(db.get_connection())
        nm.insert(title, content, session['user_id'])
        return redirect("/main")
    return render_template('add_news.html', title='Добавление новости',
                           form=form, username=session['username'])


@app.route('/delete_news/<int:news_id>', methods=['GET'])
def delete_news(news_id):
    if 'username' not in session:
        return redirect('/login')
    nm = NewsModel(db.get_connection())
    nm.delete(news_id)
    return redirect("/main")


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
