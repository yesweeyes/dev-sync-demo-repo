from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['JWT_SECRET_KEY'] = 'secretkey'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ========== Models ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=1)

# ========== Routes ==========
@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], password=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify(message="User registered successfully")

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=user.id)
        return jsonify(token=token)
    return jsonify(message="Invalid credentials"), 401

@app.route('/products', methods=['GET'])
def list_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'price': p.price} for p in products])

@app.route('/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    user_id = get_jwt_identity()
    data = request.json
    cart_item = Cart(user_id=user_id, product_id=data['product_id'], quantity=data.get('quantity', 1))
    db.session.add(cart_item)
    db.session.commit()
    return jsonify(message="Item added to cart")

@app.route('/cart', methods=['GET'])
@jwt_required()
def view_cart():
    user_id = get_jwt_identity()
    items = Cart.query.filter_by(user_id=user_id).all()
    result = []
    for item in items:
        product = Product.query.get(item.product_id)
        result.append({
            'product': product.name,
            'price': product.price,
            'quantity': item.quantity
        })
    return jsonify(result)

@app.route('/checkout', methods=['POST'])
@jwt_required()
def checkout():
    user_id = get_jwt_identity()
    Cart.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return jsonify(message="Checkout successful!")

if __name__ == '__main__':
    app.run(debug=True)
