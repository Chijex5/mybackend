import os
import jwt
import uuid
from flask import Flask, request, jsonify, url_for
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from flask_cors import CORS
from functools import wraps
from threading import Timer

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'embroconnect2@gmail.com'
app.config['MAIL_PASSWORD'] = 'hbbriqyjepmnwkud'
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
mail = Mail(app)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'sql12.freemysqlhosting.net'
app.config['MYSQL_USER'] = 'sql12716392'
app.config['MYSQL_PASSWORD'] = 'WegGxmisMs'
app.config['MYSQL_DB'] = 'sql12716392'
mysql = MySQL(app)

# JWT Configuration
app.config['SECRET_KEY'] = 'de844c12092211e93e328d53fd8a2d800345c15d34ffabec1042f8193d32687f'

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data['email']
    matric_no = data['matric_no']
    password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    fullname = data['fullname']
    phone = data['phone']
    department = data['department']
    address = data['address']
    level = data['level']

    cursor = mysql.connection.cursor()

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_email = cursor.fetchone()
    if existing_email:
        cursor.close()
        return jsonify({'error': 'Email already exists'}), 409

    cursor.execute("SELECT * FROM users WHERE matric_no = %s", (matric_no,))
    existing_matric_no = cursor.fetchone()
    if existing_matric_no:
        cursor.close()
        return jsonify({'error': 'Matriculation number already exists'}), 410

    try:
        cursor.execute(''' INSERT INTO users (public_id, email, matric_no, password, fullname, phone, department, address, level) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''', (str(uuid.uuid4()), email, matric_no, password, fullname, phone, department, address, level))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        cursor.close()
        return jsonify({'error': 'Registration Failed', 'details': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data['identifier']
    password = data['password']

    cursor = mysql.connection.cursor()
    result = cursor.execute(''' SELECT * FROM users WHERE email = %s OR matric_no = %s ''', (identifier, identifier))
    user = cursor.fetchone()
    cursor.close()

    if not user or not check_password_hash(user[4], password):
        return jsonify({'message': 'Invalid username or password'}), 401

    token = jwt.encode({'public_id': user[0], 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token}), 200

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['public_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 406
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    matric_no = data.get('matric_no')

    def get_user_by_matric_no(matric_no):
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT id, email, fullname FROM users WHERE matric_no = %s', (matric_no,))
        user = cursor.fetchone()
        cursor.close()
        return user

    user = get_user_by_matric_no(matric_no)
    if not user:
        return jsonify({'message': 'User not found!'}), 404

    token = jwt.encode({'user_id': user[0], 'exp': datetime.utcnow() + timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
    reset_link = f'https://work-please.onrender.com/reset-password/{token}'
    expires_at = datetime.utcnow() + timedelta(hours=1)

    cursor = mysql.connection.cursor()
    cursor.execute('INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)', (user[0], token, expires_at))
    mysql.connection.commit()
    cursor.close()
    print(reset_link)

    msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[user[1]])
    msg.body = f'Hi {user[2]},\n\nPlease click on the link below to reset your password:\n{reset_link}\n\nIf you did not request this, please ignore this email.'
    mail.send(msg)

    return jsonify({'message': 'Password reset email sent!'}), 200


@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = data['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 403
    
    data = request.get_json()
    new_password = data.get('password')
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

    cursor = mysql.connection.cursor()
    cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, user_id))
    mysql.connection.commit()
    cursor.execute('DELETE FROM password_reset_tokens WHERE token = %s', (token,))
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({'message': 'Password has been reset!'}), 200

@app.route('/get-user', methods=['GET'])
@token_required
def get_user(current_user):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT public_id, email, fullname, phone, department, address, level, active, role FROM users WHERE public_id = %s', (current_user,))
    user = cursor.fetchone()
    cursor.close()
    if not user:
        return jsonify({'message': 'User not found!'}), 404

    user_data = {
        'public_id': user[0],
        'email': user[1],
        'fullname': user[2],
        'phone': user[3],
        'department': user[4],
        'address': user[5],
        'level': user[6],
        'active': user[7],
        'role': user[8]
    }

    return jsonify(user_data), 200

@app.route('/create-notification', methods=['POST'])
@token_required
def create_notification(current_user):
    data = request.get_json()
    sender = data['sender']
    message = data['message']
    details = data['details']
    time = datetime.utcnow()

    cursor = mysql.connection.cursor()
    cursor.execute('''INSERT INTO notifications (user_id, sender, message, time, details) VALUES (%s, %s, %s, %s, %s)''', (current_user, sender, message, time, details))
    mysql.connection.commit()
    cursor.close()

    return jsonify({'message': 'Notification created!'}), 201

@app.route('/notifications/<int:notification_id>/read', methods=['PATCH'])
@token_required
def mark_as_read(current_user, notification_id):
    cursor = mysql.connection.cursor()
    cursor.execute('UPDATE notifications SET `read` = TRUE, read_at = %s WHERE id = %s AND user_id = %s', (datetime.utcnow(), notification_id, current_user))
    mysql.connection.commit()
    cursor.close()

    delete_time = 86400  # 24 hours in seconds
    Timer(delete_time, delete_notification, [notification_id, current_user]).start()

    return jsonify({"message": "Notification marked as read and scheduled for deletion."}), 200

def delete_notification(notification_id, user_id):
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM notifications WHERE id = %s AND user_id = %s AND `read` = TRUE', (notification_id, user_id))
    mysql.connection.commit()
    cursor.close()

@app.route('/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM notifications WHERE user_id = %s ORDER BY id DESC', (current_user,))
    notifications = cursor.fetchall()
    cursor.close()

    notifications_list = []
    for notification in notifications:
        notifications_list.append({
            'id': notification[0],
            'user_id': notification[1],
            'sender': notification[2],
            'message': notification[3],
            'time': notification[4],
            'details': notification[5]
        })

    return jsonify(notifications_list), 200

@app.route('/staff', methods=['POST'])
@token_required
def add_staff(current_user):
    data = request.json
    role = data['role']
    gender = data['gender']
    availability = data['availability']
    
    cursor = mysql.connection.cursor()

    try:
        for slot in availability:
            day = slot['day']
            from_time = slot['from']
            to_time = slot['to']

            insert_query = """
                INSERT INTO staff (user_id, role, gender, day, from_time, to_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (current_user, role, gender, day, from_time, to_time))
        
        mysql.connection.commit()
        cursor.close()

        return jsonify({'message': 'Staff added successfully'}), 201
    
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/update-profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    data = request.json
    fullname = data.get('fullname')
    phone = data.get('phone')
    department = data.get('department')
    address = data.get('address')
    level = data.get('level')

    cursor = mysql.connection.cursor()

    try:
        cursor.execute('''
            UPDATE users 
            SET fullname = %s, phone = %s, department = %s, address = %s, level = %s 
            WHERE public_id = %s
        ''', (fullname, phone, department, address, level, current_user))

        mysql.connection.commit()
        return jsonify({'message': 'User updated successfully'}), 200

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': 'Failed to update user', 'details': str(e)}), 500

    finally:
        cursor.close()

@app.route('/findbooks', methods=['GET'])
def get_books():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM books")
        books = cursor.fetchall()
        cursor.close()
        
        books_list = []
        for book in books:
            books_list.append({
                'id': book[0],
                'title': book[1],
                'author': book[2],
                'publisher': book[3],
                'year': book[4],
                'genre': book[5]
            })

        return jsonify(books_list), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
