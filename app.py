import email
from os import name
from flask import Flask, redirect, request, flash, render_template, jsonify,session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import jwt
import datetime


app= Flask(__name__)
db_username = 'postgres'
db_password = 'Musk%401702'
db_host = 'localhost'
db_port = '5432'
db_name = 'Astrotaal'

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}'
app.config['SECRET_KEY'] = 'astrotaal'
db = SQLAlchemy(app)
# bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    Name = db.Column(db.String(150), nullable=True)
    Date_of_Birth = db.Column(db.Date, nullable=True)
    Time_of_Birth = db.Column(db.Time(timezone=True), nullable=True)
    Location_of_Birth = db.Column(db.String(150), nullable=True)
    Phone_number = db.Column(db.String(150), nullable=True)
    Marital_status =db.Column(db.String(100), nullable=True)
   
# Class profile_update(db.Model):
    
    def __init__(self,email,password,Name,Date_of_Birth,Time_of_Birth,Location_of_Birth,Phone_number,Marital_status):
        self.email = email
        self.Name = Name
        self.Date_of_Birth = Date_of_Birth
        self.Time_of_Birth = Time_of_Birth
        self.Location_of_Birth = Location_of_Birth
        self.Phone_number = Phone_number
        self.Marital_status = Marital_status

        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

def generate_access_token(email):
    payload = {
        'email': email,
        'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)  # Token expiration time
    }
    token = jwt.encode(payload, 'accesss_token_secret_key', algorithm='HS256')
    return token

def verify_access_token(token):
    try:
        payload = jwt.decode(token, 'accesss_token_secret_key', algorithms=['HS256'])
        return payload['email']
    except jwt.ExpiredSignatureError:
        return 'Token expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


@app.route('/')
def index():
    return "Hello"


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # handle request
        email = request.form['email']
        password = request.form['password']
        name=request.form['Name']
        date_of_birth=request.form['Date of Birth']
        time_of_birth=request.form['Time of Birth']
        location_of_birth=request.form['Location of Birth']
        phone_number=request.form['Phone number']
        martial_status=request.form['Marital status']

         # Check if the email is already registered
        try:
            new_user = User(email=email,password=password,Name=name,Date_of_Birth=date_of_birth,Time_of_Birth=time_of_birth,Location_of_Birth=location_of_birth,Phone_number=phone_number,Marital_status=martial_status)
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')
            

        except:
            if User.query.filter_by(email=email).first():
                flash('Email already exists, try with another email.','warning')

    return render_template('register.html')



@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            # session['email'] = user.email
            # session['password'] = user.password
            access_token = generate_access_token(email)
            # print (access_token)
            # token_value = jsonify({'access_token': access_token}), 200
           # flash ('login successful','success')
            return redirect('/update_profile')
        else:
            flash ('Invalid credentials', 'error')

        # else:
            # access_token = generate_access_token(email)
            # return jsonify({'access_token': access_token.decode('UTF-8')}), 200
        #     return render_template('login.html',error='Invalid user')
    return render_template('login.html')
        
    

       

@app.route('/update_profile', methods=['GET', 'PUT'])
def update_profile():
    token = request.headers.get('Authorization')
    email=verify_access_token(token)

    data = request.form
    
    # Update user profile
    user = User.query.get(email)
    if user:
        user.name = data.get('Name')
        user.dob = datetime.strptime(data.get('Date_of_Birth'), '%d-%m-%Y').date()
        user.time_of_birth = datetime.strptime(data.get('Time_of_Birth'), '%H:%M').time()
        user.location_of_birth = data.get('Location_of_Birth')
        user.email = data.get('email')
        user.phone_number = data.get('Phone_number')
        user.marital_status = data.get('Marital_status')
        db.session.commit()
        flash('Profile updated successfully.','success')
    else:
        flash('User not found!','error')


if __name__=='__main__':
    app.run(debug=True)
    