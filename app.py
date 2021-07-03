from flask import Flask, redirect, render_template, url_for, request, flash
from flask_login.utils import login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from flask_bcrypt import Bcrypt




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ildar:1234@localhost:5432/hostel'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '12345'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)



class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    hash_pwd = db.Column(db.LargeBinary(), nullable=False)
    
    def __repr__(self):
        return f"USER_ID: {self.id}, email: {self.email} hash_pwd: {self.hash_pwd}"


class Room(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    room_number = db.Column(db.Integer(), nullable=False)
    seats_number = db.Column(db.Integer(), nullable=False)
    comment = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"ROOM_ID: {self.id}, room_number: {self.room_number}"



db.create_all()

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def main():
    return render_template('main.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        if email and password and password2:
            if password == password2:
                email_db = User.query.filter_by(email=email).first()
                if email_db:
                    flash('Such user with email already have an account peace of shit!')
                else:
                    hash_pwd = bcrypt.generate_password_hash(password)
                    new_user = User(email=email, hash_pwd=hash_pwd)
                    db.session.add(new_user)
                    db.session.commit()
                    return redirect(url_for('login'))
            else:
                flash('Your password are different! Type the same passwords fucking asshole!')
        else:
            flash('Please fill all fucking fields')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method =='POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email and password:
            email_db = User.query.filter_by(email=email).first()
            if email_db:
                if bcrypt.check_password_hash(email_db.hash_pwd, password):
                    login_user(email_db)
                    next_page = request.args.get('next')
                    if email == 'lovely-bear@mail.ru':
                        return redirect(url_for('admin_dashboard'))
                    if next_page:
                        return redirect(next_page)
                    else:
                        return redirect(url_for('dashboard'))
                else:
                    flash('Incorrect Login or password ')
            else:
                flash('There are no such Fucking user!')
        else:
            flash('Fill all fields!')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    all_rooms = Room.query.all()
    return render_template('admin_dashboard.html', rooms=all_rooms)


@app.route('/changing-rooms', methods=['GET', 'POST'])
@login_required
def changing_rooms():
    all_rooms = Room.query.all()
    return render_template('changing_rooms.html', rooms=all_rooms)


@app.route('/add-rooms', methods=['GET', 'POST'])
@login_required
def add_room():
    if request.method == 'POST':
        room_number = request.form.get('room_number')
        seats_number = request.form.get('seats_number')
        comment = request.form.get('comment')

        new_room = Room(room_number=room_number, seats_number=seats_number, comment=comment)
        db.session.add(new_room)
        db.session.commit()
        return redirect(url_for('changing_rooms'))
    return render_template('add_room.html')



@app.after_request
def redirect_to_sign_in(response):
    if response.status_code == 401:
        return redirect(url_for('login') + '?next=' + request.url)
    else:
        return response




