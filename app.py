from flask import Flask, request, jsonify #handles api requestes and incoming json payloads then convert the python dictionaries to json using jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity #Handles authentication using JSON Web Tokens (JWT)
import mysql.connector
import pyotp
import qrcode
import io #Handles in-memory binary operations (used for QR code conversion).
import base64
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__) #Creates an instance of the Flask web application, which will be used to define API routes.

# intitialiaze JWT and authenticate it
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
jwt = JWTManager(app)


db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="my_secure_app"
)
cursor = db.cursor()
@app.route('/register', methods=['POST']) #defines an API endpoint /register, which accepts only POST requests.
def register():
    data = request.json #extracts JSON data sent by the client (e.g., a frontend or Postman request).
    username = data['username']
    password = generate_password_hash(data['password'])

    # Generate a secret key for Google Authenticator
    secret = pyotp.random_base32()

    try: #inserts the new user’s details into the users table
        cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)",
                       (username, password, secret))
        db.commit()
    except mysql.connector.IntegrityError:
        return jsonify({"message": "Username already exists"}), 400

    # Generate QR Code for Google Authenticator
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="FlaskAuthApp") #Generates a URI (Uniform Resource Identifier) for Google Authenticator. This URI contains: secret → The unique key for the user.name=username → Links the QR code to the user's username.issuer_name="FlaskAuthApp" → Identifies the application.
    qr = qrcode.make(otp_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return jsonify({"message": "User registered successfully", "qr_code": qr_base64})
@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    username = data['username']
    otp_code = data['otp_code']

    cursor.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"message": "User not found"}), 404

    secret = user[0]
    totp = pyotp.TOTP(secret)

    if totp.verify(otp_code):
        return jsonify({"message": "2FA verification successful"})
    else:
        return jsonify({"message": "Invalid OTP code"}), 400
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    otp_code = data['otp_code']

    cursor.execute("SELECT password, twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user[0], password):
        return jsonify({"message": "Invalid username or password"}), 401

    secret = user[1]
    totp = pyotp.TOTP(secret)

    if not totp.verify(otp_code):
        return jsonify({"message": "Invalid OTP code"}), 400

    # Generate JWT Token
    access_token = create_access_token(identity=username, expires_delta=False)

    return jsonify({"access_token": access_token})
@app.route('/product', methods=['POST'])
@jwt_required()
def create_product():
    data = request.json
    name, description, price, quantity = data['name'], data['description'], data['price'], data['quantity']

    cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                   (name, description, price, quantity))
    db.commit()

    return jsonify({"message": "Product created successfully"})
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()

    return jsonify(products)
@app.route('/product/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    data = request.json
    name, description, price, quantity = data['name'], data['description'], data['price'], data['quantity']

    cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                   (name, description, price, quantity, product_id))
    db.commit()

    return jsonify({"message": "Product updated successfully"})
@app.route('/product/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
    db.commit()

    return jsonify({"message": "Product deleted successfully"})

@app.route('/')
def home():
    return "Hello, Flask is working!"

if __name__ == '__main__':
    app.run(debug=True)

