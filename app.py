import os
from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
import uuid
import jwt
import datetime
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configure MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'my_app_user'
app.config['MYSQL_PASSWORD'] = '08023029886'
app.config['MYSQL_DB'] = 'my_app'

mysql = MySQL(app)

# Secret key for JWT encoding
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

    # Check if email or matric_no already exists
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_email = cursor.fetchone()
    if existing_email:
        cursor.close()
        return jsonify({'error': 'Email already exists'}), 409

    # Check if matric_no already exists
    cursor.execute("SELECT * FROM users WHERE matric_no = %s", (matric_no,))
    existing_matric_no = cursor.fetchone()
    if existing_matric_no:
        cursor.close()
        return jsonify({'error': 'Matriculation number already exists'}), 410


    # Insert new user into the database
    try:
        cursor = mysql.connection.cursor()
        cursor.execute(''' INSERT INTO users (public_id, email, matric_no, password, fullname, phone, department, address, level) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''', (str(uuid.uuid4()), email, matric_no, password, fullname, phone, department, address, level))
        mysql.connection.commit()
        cursor.close()
        return jsonify(matric_no)
    except Exception as e:
        return jsonify({'error': 'Registration Failed'}), 404

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data['identifier']
    password = data['password']

    cursor = mysql.connection.cursor()
    result = cursor.execute(''' SELECT * FROM users WHERE email = %s OR matric_no = %s ''', (identifier, identifier))
    user = cursor.fetchone()

    if not user or not check_password_hash(user[4], password):
        return jsonify({'message': 'Invalid username or password'}), 401

    token = jwt.encode({'public_id': user[0], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')

    

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



@app.route('/get-user', methods=['GET'])
@token_required
def get_user(current_user):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT public_id, email, fullname, phone, department, address, level, active, role FROM users LEFT JOIN staff ON users.id = staff.user_id WHERE users.id = %s', (current_user,))
    user = cursor.fetchone()
    cursor.close()
    if not user:
        print(current_user)
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
    time = datetime.datetime.utcnow()

    cursor = mysql.connection.cursor()
    cursor.execute(''' INSERT INTO notifications (id, sender, message, time, details) VALUES (%s, %s, %s, %s, %s)''', (current_user, sender, message, time, details))
    mysql.connection.commit()
    cursor.close()

    return jsonify({'message': 'Notification created!'}), 201

@app.route('/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM notifications WHERE id = %s ORDER BY user_id DESC', (current_user,))
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
    
    try:
        cursor = mysql.connection.cursor()

        for slot in availability:
            day = slot['day']
            from_time = slot['from']
            to_time = slot['to']

            # Insert staff data using raw SQL for each availability slot
            insert_query = """
                INSERT INTO staff (user_id, role, gender, day, from_time, to_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (current_user, role, gender, day, from_time, to_time))
        
        mysql.connection.commit()
        cursor.close()

        return jsonify({'message': 'Staff added successfully'})
    
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
            WHERE id = %s
        ''', (fullname, phone, department, address, level, current_user))

        mysql.connection.commit()
        print(level)
        
        return {'message': 'User updated successfully'}, 200

    except Exception as e:
        
        print(f"Error updating user: {str(e)}")
        return {'error': 'Failed to update user'}, 500

    finally:
        cursor.close()



@app.route('/findbooks', methods=['GET'])
def get_books():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM books")
        books = cursor.fetchall()
        
        return jsonify(books)
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return jsonify({'error': str(err)}), 500
    finally:
        cursor.close()
        


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

