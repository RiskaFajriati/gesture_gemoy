import numpy as np
from tensorflow.keras.preprocessing.image import load_img
from functools import wraps
from flask import Flask, jsonify, request
import pymysql
import io
import pickle
import cv2
from PIL import Image
from dotenv import load_dotenv
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from marshmallow import Schema, fields, validate
import jwt

# #################### ENV #########################
load_dotenv()

app = Flask(__name__)
pick_read = open('knn_model.pickle', 'rb')
model = pickle.load(pick_read)
pick_read.close()
app.config['MYSQL_HOST'] = os.getenv("DB_HOST")
app.config['MYSQL_USER'] = os.getenv("DB_USER")
app.config['MYSQL_PASSWORD'] = os.getenv("DB_PASSWORD")
app.config['MYSQL_DB'] = os.getenv("DB_NAME")
app.config['IMAGE_UPLOADS'] = "/home/azureuser/gesture_gemoy"
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
mysql = pymysql.connect(
    host=app.config['MYSQL_HOST'],
    user=app.config['MYSQL_USER'],
    password=app.config['MYSQL_PASSWORD'],
    db=app.config['MYSQL_DB'],
    ssl_ca='DigiCertGlobalRootCA.crt.pem'
)

def get_user_id():
    headers = request.headers['Authorization']
    token = headers.split()[1]
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    return str(data['id'])



# Validator Class

class LoginSchema(Schema):
    user = fields.String(
        required=True,
        validate=validate.Length(4),
        error_messages={
            "required": "Username harus diisi",
            "validator_failed": "Username minimal 4 huruf"
        }
    )
    password = fields.String(
        required=True,
        validate=validate.Length(8),
        error_messages={
            "required": "Password harus diisi",
            "validator_failed": "Password minimal 8 huruf"
        }
    )




##################### JWT #########################


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'Authorization' in request.headers:
            headers = request.headers['Authorization']
            token = headers.split()[1]
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token tidak ditemukan !!'}), 401
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = getUsersbyId(data['id'])
        except Exception as e:
            print(e)
            return jsonify({
                'message': 'Token tidak valid !!'
            }), 401
        # returns the current logged in users context to the routes
        return f(current_user, *args, **kwargs)

    return decorated


##################### Login #########################
@app.route('/login', methods=['POST'])
def login():

    try:
        data = request.get_json()
        login_schema = LoginSchema()
        errors = login_schema.validate(data)
        if errors:
            return jsonify({"error": errors}), 422
        user = getUsersbyUsername(data["user"])
        if not user:
            # returns 401 if user does not exist
            return jsonify({
                'message': 'Akun tidak ada !!'
            }), 400

        if check_password_hash(user['password'], data["password"]):
            # generates the JWT Token
            print("HOHOHOHOHO")
            token = jwt.encode({
                'id': user['id'],
                'exp': datetime.utcnow() + timedelta(minutes=131400)
            }, app.config['SECRET_KEY'])
            encoded_jwt = token.decode('UTF-8')
            print(type(token))
            return jsonify({"token": encoded_jwt,
                            "status": user['status']}), 200
        # returns 403 if password is wrong
        return jsonify({"message": "Akun tidak bisa di verifikasi!"}), 403
    except Exception as e:
        return jsonify({"message": e}), 400


##################### Register #########################
@app.route('/register', methods=['POST'])
def signup():
    try:
        users = request.json['user']
        status = request.json['status']
        password = request.json['password']
        # checking for existing user
        user = getUsersbyUsername(users)
        if not user:
            cur = mysql.cursor()
            cur.execute(
                '''INSERT INTO users (user, password, status) VALUES (%s, %s, %s)''', (users, generate_password_hash(password), status))
            mysql.commit()
            cur.close()
            return jsonify({"message": "Berhasil Didaftarkan"}), 201
        else:
            return jsonify({"message": "Username sudah ada."}), 400
    except Exception as e:
        return jsonify({"message": e}), 400


######################## Do SOmethink here ############################
@app.route("/upload", methods=["POST"])
@token_required
def upload_image(current_user):
    if request.files:
        # Check Image Mimetype
        file = request.files["image"]
        if (file.mimetype != 'image/jpeg' and file.mimetype != 'image/png') :
            return jsonify({"message": "Gunakan Format jpeg atau png!"}), 400
        print(file.mimetype)
        # Read Image
        # image = file.read()
        # image = Image.open(io.BytesIO(image))
        file_path = os.path.join(app.config["IMAGE_UPLOADS"], file.filename)
        file.save(file_path)
        img = load_img(file_path, target_size=(100, 100))
        pca = extract_features(img)
        print(pca[0].shape)
        hehe = model.predict(pca[0].reshape(1, -1))
        # Do model prediction
        # delete photo
        os.remove(file_path)
        # Return response
        return jsonify({
            "message": "some-prediction value",
            "data": hehe
            }), 200
    else:
        return jsonify({"message": "Somethink went wronk"}), 400

######################################################################


##################### Hello Wolrd #########################
@app.route('/', methods=['GET'])
@token_required
def helloworld(current_user):
    if (request.method == 'GET'):
        data = {"data": "Hello World"}
        return jsonify(data)

@app.route('/check', methods=['GET'])
@token_required
def check_limit(current_user):
    if current_user["status"] == 0:
        try:
            with limiter.limit("50 per day", key_func=get_user_id):
                data = {"data": "Hello Misqueen"}
                return jsonify(data)
        except RateLimitExceeded:
            data = {"message": "Limit Exceed"}
            return jsonify(data), 429
    else:
        try:
            with limiter.limit("75 per day", key_func=get_user_id):
                data = {"data": "Hello Sultan"}
                return jsonify(data)
        except RateLimitExceeded:
            data = {"message": "Limit Exceed"}
            return jsonify(data), 429
            
    
##################### All users #########################
@app.route('/users', methods=['GET'])
@token_required
def getUsers(current_user):
    try:
        items = []
        cur = mysql.cursor()
        cur.execute('''SELECT * FROM users''')
        data = cur.fetchall()
        cur.close()
        for item in data:
            item = {
                'id': item[0],
                'user': item[1],
                'password': item[2],
                'status': item[3],
            }
            items.append(item)
        return jsonify(items), 200
    except Exception as e:
        item = {
            'status': False,
            'message': f"{e}",
        }
        items.append(item)
        return jsonify(items), 500


##################### User By Id #########################
@app.route('/users/<int:id>', methods=['GET'])
def getUserById(id):
    try:
        response = getUsersbyId(id)
        return jsonify(response), 200
    except Exception as e:
        response = {
            'status': False,
            'message': f"{e}",
        }
        return jsonify(response), 500

################### Handle Not Found #####################


@app.errorhandler(404)
def not_found_error(e):
    return jsonify({'message': 'Not Found'}), 404

################## Custom Function #####################


def getUsersbyId(params):
    cur = mysql.cursor()
    cur.execute('''SELECT * FROM users WHERE id = %s''', (params,))
    data = cur.fetchall()
    cur.close()
    if not data:
        response = None
    else:
        response = {
            'id': data[0][0],
            'user': data[0][1],
            'password': data[0][2],
            'status': data[0][3],
        }
    return response


def getUsersbyUsername(params):
    cur = mysql.cursor()
    cur.execute('''SELECT * FROM users WHERE user = %s''', (params,))
    data = cur.fetchall()
    cur.close()
    if not data:
        response = None
    else:
        response = {
            'id': data[0][0],
            'user': data[0][1],
            'password': data[0][2],
            'status': data[0][3],
        }
    return response


if __name__ == '__main__':
    app.run()
