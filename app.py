from random import randint
import numpy as np
from sklearn.decomposition import PCA
from functools import wraps
from flask import Flask, jsonify, request
import cv2
import pickle
from PIL import Image
import os
import time

# #################### ENV #########################

app = Flask(_name_)
pick_read = open('knn_model.pickle', 'rb')
model = pickle.load(pick_read)
pick_read.close()
# app.config['MYSQL_HOST'] = os.getenv("DB_HOST")
# app.config['MYSQL_USER'] = os.getenv("DB_USER")
# app.config['MYSQL_PASSWORD'] = os.getenv("DB_PASSWORD")
# app.config['MYSQL_DB'] = os.getenv("DB_NAME")
app.config['IMAGE_UPLOADS'] = "/home/azureuser/gesture_gemoy"
# app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
# mysql = pymysql.connect(
#     host=app.config['MYSQL_HOST'],
#     user=app.config['MYSQL_USER'],
#     password=app.config['MYSQL_PASSWORD'],
#     db=app.config['MYSQL_DB'],
#     ssl_ca='DigiCertGlobalRootCA.crt.pem'
# )

# def get_user_id():
#     headers = request.headers['Authorization']
#     token = headers.split()[1]
#     data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#     return str(data['id'])



# Validator Class

# class LoginSchema(Schema):
#     user = fields.String(
#         required=True,
#         validate=validate.Length(4),
#         error_messages={
#             "required": "Username harus diisi",
#             "validator_failed": "Username minimal 4 huruf"
#         }
#     )
#     password = fields.String(
#         required=True,
#         validate=validate.Length(8),
#         error_messages={
#             "required": "Password harus diisi",
#             "validator_failed": "Password minimal 8 huruf"
#         }
#     )




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
# @app.route('/login', methods=['POST'])
# def login():

#     try:
#         data = request.get_json()
#         login_schema = LoginSchema()
#         errors = login_schema.validate(data)
#         if errors:
#             return jsonify({"error": errors}), 422
#         user = getUsersbyUsername(data["user"])
#         if not user:
#             # returns 401 if user does not exist
#             return jsonify({
#                 'message': 'Akun tidak ada !!'
#             }), 400

#         if check_password_hash(user['password'], data["password"]):
#             # generates the JWT Token
#             print("HOHOHOHOHO")
#             token = jwt.encode({
#                 'id': user['id'],
#                 'exp': datetime.utcnow() + timedelta(minutes=131400)
#             }, app.config['SECRET_KEY'])
#             encoded_jwt = token.decode('UTF-8')
#             print(type(token))
#             return jsonify({"token": encoded_jwt,
#                             "status": user['status']}), 200
#         # returns 403 if password is wrong
#         return jsonify({"message": "Akun tidak bisa di verifikasi!"}), 403
#     except Exception as e:
#         return jsonify({"message": e}), 400


##################### Register #########################
# @app.route('/register', methods=['POST'])
# def signup():
#     try:
#         users = request.json['user']
#         status = request.json['status']
#         password = request.json['password']
#         # checking for existing user
#         user = getUsersbyUsername(users)
#         if not user:
#             cur = mysql.cursor()
#             cur.execute(
#                 '''INSERT INTO users (user, password, status) VALUES (%s, %s, %s)''', (users, generate_password_hash(password), status))
#             mysql.commit()
#             cur.close()
#             return jsonify({"message": "Berhasil Didaftarkan"}), 201
#         else:
#             return jsonify({"message": "Username sudah ada."}), 400
#     except Exception as e:
#         return jsonify({"message": e}), 400

######################## TEst ############################
@app.route("/test", methods=["GET"])
def masa_depan_cerah():
    return jsonify({
        "message": "Hasil Klasifikasi",
        "data": randint(1, 10)
        }), 200

@app.route('/static/<path:filename>')
def serve_public_file(filename):
    return send_from_directory('static', filename)

######################## Do SOmethink here ############################
@app.route("/upload", methods=["POST"])
def upload_image():
    if request.files:
        # Check Image Mimetype
        t0 = time.perf_counter_ns()

        file = request.files["image"]
        if (file.mimetype != 'image/jpeg' and file.mimetype != 'image/png') :
            return jsonify({"message": "Gunakan Format jpeg atau png!"}), 400
        print(file.mimetype)
        # Read Image
        # image = file.read()
        # image = Image.open(io.BytesIO(image))
        file_path = os.path.join(app.config["IMAGE_UPLOADS"], file.filename)
        file.save(file_path)
        img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        imgResize = cv2.resize(img, (63, 63))
        pca = extract_features(imgResize)
        hehe = model.predict(pca[0].reshape(1, -1))
        # hehe2 = model.predict_proba(pca[0].reshape(1, -1))
        # Do model prediction
        # delete photo
        if os.path.exists(file_path):
            os.remove(file_path)
        # Return response
        
        # FOTO
        print(type(imgResize))

        file_path = os.path.join('static', file.filename)
        image = Image.fromarray(img, 'RGB') # ubah pca dengan variable yang dinginkan
        image.save(file_path, format='PNG')


       

        baseUrl = 'http://4.145.113.194:5000/static/'
        fileUrl = f'{baseUrl}{file.filename}'
        tdur = time.perf_counter_ns() - t0
        return jsonify({
            "message": "Hasil Klasifikasi",
            "data": hehe.item(),
            "link": fileUrl,
            "waktu":tdur/1e9
            }), 200
    else:
        return jsonify({"message": "Somethink went wronk"}), 400

######################################################################


################### Handle Not Found #####################


@app.errorhandler(404)
def not_found_error(e):
    return jsonify({'message': 'Not Found'}), 404

################## Custom Function #####################


def extract_features(images):
    features = []
    for image in images:
        flattened_image = image.flatten()
        features.append(flattened_image)

    pca = PCA(n_components=63)  # Ubah jumlah komponen sesuai kebutuhan
    reduced_features = pca.fit_transform(features)

    return reduced_features

if _name_ == '_main_':
    app.run()