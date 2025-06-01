from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, abort
from flask_login import LoginManager, login_required, current_user, logout_user, login_user
from models import db, User, Product, Category, Cart, ChatRoom, ChatMessage, Order, OrderItem
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func
from datetime import datetime, timedelta
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
from flask import send_from_directory

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hG72zKFfRNV9M8qA3LYXtWDJ6Pc1Z5QB'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cosmetic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

socketio = SocketIO(app, cors_allowed_origins="*")

ADMIN_CREDENTIALS = {
    "email": "admin@example.com",
    "password": "admin123"
}

# Конфигурация для загрузки файлов
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


# Инициализация расширений
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_admin_user():
    admin = User.query.filter_by(email=ADMIN_CREDENTIALS['email']).first()
    if not admin:
        admin = User(
            username='admin',
            email=ADMIN_CREDENTIALS['email'],
            password_hash=generate_password_hash(ADMIN_CREDENTIALS['password']),
            first_name='Vera',
            last_name='Kanunnikava',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Администратор создан!")

# Создание базы данных (при первом запуске)
with app.app_context():
    db.create_all()
    create_admin_user()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))
    return render_template('admin/admin.html')

@app.route('/admin/products')
@login_required
def admin_products():
    if not current_user.is_admin:
        abort(403)

    products = Product.query.all()
    return render_template('admin/products.html', products=products)


@app.route('/admin/product/new', methods=['GET', 'POST'])
@login_required
def admin_new_product():
    if not current_user.is_admin:
        abort(403)

    if request.method == 'POST':
        try:
            name = request.form.get('name')
            category_id = request.form.get('category_id')
            price = request.form.get('price')
            description = request.form.get('description', '')
            stock = request.form.get('stock', 0)
            image = request.files.get('image')

            if not all([name, category_id, price]):
                flash('Пожалуйста, заполните все обязательные поля', 'danger')
                return redirect(url_for('admin_new_product'))

            try:
                category_id = int(category_id)
                price = float(price)
                stock = int(stock)
            except ValueError:
                flash('Некорректные числовые значения', 'danger')
                return redirect(url_for('admin_new_product'))

            category = Category.query.get(category_id)
            if not category:
                flash('Указанная категория не существует', 'danger')
                return redirect(url_for('admin_new_product'))

            image_filename = None
            if image and image.filename:
                if not allowed_file(image.filename):
                    flash('Недопустимый формат изображения. Разрешены: png, jpg, jpeg, gif', 'danger')
                    return redirect(url_for('admin_new_product'))

                # Генерируем уникальное имя файла
                ext = image.filename.rsplit('.', 1)[1].lower()
                image_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}.{ext}"
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)

                try:
                    image.save(image_path)
                except Exception as e:
                    flash('Ошибка при сохранении изображения', 'danger')
                    app.logger.error(f'Error saving image: {str(e)}')
                    return redirect(url_for('admin_new_product'))

            product = Product(
                name=name,
                category_id=category_id,
                price=price,
                description=description,
                stock=stock,
                image=image_filename
            )

            db.session.add(product)
            db.session.commit()
            flash('Товар успешно добавлен', 'success')
            return redirect(url_for('admin_products'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error adding product: {str(e)}')
            flash('Произошла ошибка при добавлении товара', 'danger')

    categories = Category.query.order_by(Category.name).all()
    return render_template('admin/new_product.html', categories=categories)


@app.route('/api/products', methods=['GET', 'POST'])
def handle_products():
    if request.method == 'GET':
        try:
            products = Product.query.order_by(Product.created_at.desc()).all()
            return jsonify({
                "success": True,
                "products": [product.to_dict() for product in products]
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    elif request.method == 'POST':
        try:
            # Если запрос отправлен как form-data, то извлекаем данные из формы
            if request.content_type and request.content_type.startswith('multipart/form-data'):
                name = request.form.get('name')
                category_value = request.form.get('category')
                price = request.form.get('price')
                description = request.form.get('description', '')
                stock = request.form.get('stock', 0)

                # Обработка изображения
                image = request.files.get('image')
                image_filename = None
                if image and image.filename:
                    if not allowed_file(image.filename):
                        return jsonify({"success": False,
                                        "error": "Недопустимый формат изображения. Разрешены: png, jpg, jpeg, gif"}), 400
                    ext = image.filename.rsplit('.', 1)[1].lower()
                    # Генерируем уникальное имя файла
                    image_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}.{ext}"
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                    image.save(image_path)

                # Поиск существующей категории или её создание
                category = Category.query.filter_by(name=category_value).first()
                if not category:
                    category = Category(name=category_value)
                    db.session.add(category)
                    db.session.commit()

                product = Product(
                    name=name,
                    category_id=category.id,
                    price=float(price),
                    description=description,
                    stock=int(stock),
                    image=image_filename
                )
                db.session.add(product)
                db.session.commit()
                return jsonify({"success": True, "product": product.to_dict()}), 201
            else:
                # Если запрос передан в формате JSON
                data = request.get_json()
                required_fields = ['name', 'category', 'price']
                if not all(field in data for field in required_fields):
                    return jsonify({"success": False, "error": "Missing required fields"}), 400

                category = Category.query.filter_by(name=data['category']).first()
                if not category:
                    category = Category(name=data['category'])
                    db.session.add(category)
                    db.session.commit()

                product = Product(
                    name=data['name'],
                    category_id=category.id,
                    price=float(data['price']),
                    description=data.get('description', ''),
                    stock=int(data.get('stock', 0))
                )
                db.session.add(product)
                db.session.commit()
                return jsonify({"success": True, "product": product.to_dict()}), 201

        except ValueError as e:
            db.session.rollback()
            return jsonify({"success": False, "error": "Invalid numeric value"}), 400
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "error": str(e)}), 500


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@login_required
def update_product(product_id):
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    product = Product.query.get_or_404(product_id)

    try:
        # Handle form data (for image upload) or JSON data
        if request.content_type.startswith('multipart/form-data'):
            # Process form data with potential file upload
            name = request.form.get('name')
            category_id = request.form.get('category_id')
            price = request.form.get('price')
            description = request.form.get('description', '')
            stock = request.form.get('stock', 0)

            # Handle image upload if present
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename and allowed_file(file.filename):
                    # Delete old image if exists
                    if product.image:
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
                        except OSError:
                            pass

                    # Save new image
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    product.image = filename
                elif file and file.filename and not allowed_file(file.filename):
                    return jsonify({"success": False, "error": "Недопустимый формат изображения"}), 400

            # Update other fields
            if name: product.name = name
            if category_id:
                try:
                    product.category_id = int(category_id)
                except ValueError:
                    return jsonify({"success": False, "error": "Некорректный ID категории"}), 400
            if price:
                try:
                    product.price = float(price)
                except ValueError:
                    return jsonify({"success": False, "error": "Некорректная цена"}), 400
            if description: product.description = description
            if stock:
                try:
                    product.stock = int(stock)
                except ValueError:
                    return jsonify({"success": False, "error": "Некорректное количество"}), 400

        else:
            # Process JSON data
            data = request.get_json()

            # Update category if needed
            if 'category' in data:
                category = Category.query.filter_by(name=data['category']).first()
                if not category:
                    category = Category(name=data['category'])
                    db.session.add(category)
                    db.session.commit()
                product.category_id = category.id

            # Update other fields
            if 'name' in data: product.name = data['name']
            if 'price' in data: product.price = float(data['price'])
            if 'description' in data: product.description = data['description']
            if 'stock' in data: product.stock = int(data['stock'])

        db.session.commit()
        return jsonify({"success": True, "product": product.to_dict()})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    return jsonify({'success': True}), 200

@app.route('/check-admin')
@login_required
def check_admin():
    return jsonify({'is_admin': current_user.is_admin})  # Проверяем через current_user



@app.route('/api/categories', methods=['GET', 'POST'])
def handle_categories():
    if request.method == 'GET':
        categories = Category.query.order_by(Category.name).all()
        return jsonify({
            "success": True,
            "categories": [
                {"id": c.id, "name": c.name, "description": c.description}
                for c in categories
            ]
        })

    elif request.method == 'POST':
        data = request.get_json()
        new_cat = Category(name=data['name'], description=data.get('description', ''))
        db.session.add(new_cat)
        db.session.commit()
        return jsonify({"success": True, "category": {"id": new_cat.id, "name": new_cat.name}})

@app.route('/api/categories/<int:category_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required  # желательно
def handle_single_category(category_id):
    category = Category.query.get_or_404(category_id)

    if request.method == 'GET':
        return jsonify({"success": True, "category": {
            "id": category.id,
            "name": category.name,
            "description": category.description
        }})

    elif request.method == 'PUT':
        data = request.get_json()
        category.name = data.get('name', category.name)
        category.description = data.get('description', category.description)
        db.session.commit()
        return jsonify({"success": True})

    elif request.method == 'DELETE':
        try:
            # Переназначаем товары в "Без категории" (если есть)
            uncategorized = Category.query.filter_by(name="Без категории").first()
            if not uncategorized:
                uncategorized = Category(name="Без категории")
                db.session.add(uncategorized)
                db.session.flush()

            for product in category.products:
                product.category_id = uncategorized.id

            db.session.delete(category)
            db.session.commit()
            return jsonify({"success": True})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/products/<int:product_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def handle_single_product(product_id):
    product = Product.query.get_or_404(product_id)

    # Если запрос GET — возвращаем данные товара всем авторизованным
    if request.method == 'GET':
        return jsonify({"success": True, "product": product.to_dict()})

    # Для PUT и DELETE проверяем, что пользователь — администратор
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    if request.method == 'PUT':
        try:
            if request.content_type.startswith('multipart/form-data'):
                # Обработка form-data (в том числе файл)
                name = request.form.get('name')
                category_id = request.form.get('category_id')
                price = request.form.get('price')
                description = request.form.get('description', '')
                stock = request.form.get('stock', 0)
                if 'image' in request.files:
                    file = request.files['image']
                    if file and file.filename and allowed_file(file.filename):
                        if product.image:
                            try:
                                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
                            except OSError:
                                pass
                        ext = file.filename.rsplit('.', 1)[1].lower()
                        filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}.{ext}"
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        product.image = filename
                    elif file and file.filename and not allowed_file(file.filename):
                        return jsonify({"success": False, "error": "Недопустимый формат изображения"}), 400
                # Обновление других полей
                if name:
                    product.name = name
                if category_id:
                    try:
                        product.category_id = int(category_id)
                    except ValueError:
                        return jsonify({"success": False, "error": "Некорректный ID категории"}), 400
                if price:
                    try:
                        product.price = float(price)
                    except ValueError:
                        return jsonify({"success": False, "error": "Некорректная цена"}), 400
                if description:
                    product.description = description
                if stock:
                    try:
                        product.stock = int(stock)
                    except ValueError:
                        return jsonify({"success": False, "error": "Некорректное количество"}), 400
            else:
                # Обработка JSON данных
                data = request.get_json()
                if 'name' in data:
                    product.name = data['name']
                if 'category' in data:
                    category = Category.query.filter_by(name=data['category']).first()
                    if not category:
                        category = Category(name=data['category'])
                        db.session.add(category)
                        db.session.commit()
                    product.category_id = category.id
                if 'price' in data:
                    product.price = float(data['price'])
                if 'description' in data:
                    product.description = data['description']
                if 'stock' in data:
                    product.stock = int(data['stock'])
            db.session.commit()
            return jsonify({"success": True, "product": product.to_dict()})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "error": str(e)}), 400

    elif request.method == 'DELETE':
        try:
            if product.image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
                except OSError:
                    pass
            db.session.delete(product)
            db.session.commit()
            return jsonify({"success": True})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "error": str(e)}), 500


@app.route('/products')
def product_list():
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('products.html', products=products)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/users', methods=['GET'])
@login_required
def handle_users():
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({
        "success": True,
        "users": [{
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            "created_at": user.created_at.isoformat(),
            "is_admin": user.is_admin
        } for user in users]
    })


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def handle_single_user(user_id):
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    if current_user.id == user_id:
        return jsonify({"success": False, "error": "Нельзя удалить самого себя"}), 400

    user = User.query.get_or_404(user_id)

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


# Добавьте этот endpoint в ваш Flask app
@app.route('/check-auth')
def check_auth():
    return jsonify({
        'isAuthenticated': current_user.is_authenticated,
        'username': current_user.username if current_user.is_authenticated else None,
        'is_admin': current_user.is_admin if current_user.is_authenticated else False
    })

# Обновите обработчик /login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() if request.is_json else request.form
    username = data.get('username')
    password = data.get('password')
    remember = data.get('remember', False)

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        login_user(user, remember=remember)
        return jsonify({
            'success': True,
            'message': 'Вход выполнен успешно',
            'is_admin': user.is_admin
        })

    return jsonify({
        'success': False,
        'message': 'Неверное имя пользователя или пароль'
    }), 401


# Обновите обработчик /register
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() if request.is_json else request.form

    required_fields = ['username', 'email', 'password', 'first_name', 'last_name']
    if not all(field in data for field in required_fields):
        return jsonify({
            'success': False,
            'message': 'Не все обязательные поля заполнены'
        }), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({
            'success': False,
            'message': 'Имя пользователя уже занято'
        }), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({
            'success': False,
            'message': 'Email уже используется'
        }), 400

    try:
        user = User(
            username=data['username'],
            email=data['email'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone=data.get('phone'),
            password_hash=generate_password_hash(data['password']),
            role='user',
            is_admin=False
        )

        db.session.add(user)
        db.session.commit()

        login_user(user)

        return jsonify({
            'success': True,
            'message': 'Регистрация прошла успешно'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Ошибка регистрации: {str(e)}'
        }), 500


@app.route('/api/cart', methods=['GET', 'POST', 'DELETE'])
@login_required
def handle_cart():
    if request.method == 'GET':
        cart_items = Cart.query.filter_by(user_id=current_user.id).all()
        return jsonify({
            "success": True,
            "cart": [{
                "id": item.id,
                "product": item.product.to_dict(),
                "quantity": item.quantity
            } for item in cart_items]
        })

    elif request.method == 'POST':
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)

        product = Product.query.get_or_404(product_id)

        # Проверяем, есть ли уже такой товар в корзине
        cart_item = Cart.query.filter_by(
            user_id=current_user.id,
            product_id=product_id
        ).first()

        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = Cart(
                user_id=current_user.id,
                product_id=product_id,
                quantity=quantity
            )
            db.session.add(cart_item)

        db.session.commit()
        return jsonify({"success": True})

    elif request.method == 'DELETE':
        # Очистка всей корзины
        Cart.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({"success": True})


@app.route('/api/cart/<int:item_id>', methods=['PUT', 'DELETE'])
@login_required
def handle_cart_item(item_id):
    cart_item = Cart.query.filter_by(
        id=item_id,
        user_id=current_user.id
    ).first_or_404()

    if request.method == 'PUT':
        data = request.get_json()
        quantity = data.get('quantity', 1)

        if quantity <= 0:
            db.session.delete(cart_item)
        else:
            cart_item.quantity = quantity

        db.session.commit()
        return jsonify({"success": True})

    elif request.method == 'DELETE':
        db.session.delete(cart_item)
        db.session.commit()
        return jsonify({"success": True})



@app.route('/api/orders/<int:order_id>', methods=['PUT'])
@login_required
def update_order_status(order_id):
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    try:
        order = Order.query.get_or_404(order_id)
        data = request.get_json()

        if 'status' in data:
            order.status = data['status']
            db.session.commit()

        return jsonify({"success": True})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/user', methods=['GET', 'PUT', 'DELETE'])
@login_required
def handle_user_profile():
    if request.method == 'GET':
        return jsonify({
            'username': current_user.username,
            'first_name': current_user.first_name,
            'last_name': current_user.last_name,
            'email': current_user.email,
            'phone': current_user.phone,
            'address': current_user.address
        })

    elif request.method == 'PUT':
        data = request.get_json()

        # Проверка уникальности username
        if 'username' in data and data['username'] != current_user.username:
            existing_user = User.query.filter_by(username=data['username']).first()
            if existing_user:
                return jsonify({'success': False, 'message': 'Это имя пользователя уже занято'}), 400

        # Проверка уникальности email
        if 'email' in data and data['email'] != current_user.email:
            existing_email = User.query.filter_by(email=data['email']).first()
            if existing_email:
                return jsonify({'success': False, 'message': 'Этот email уже используется'}), 400

        # Обновляем данные пользователя
        if 'first_name' in data:
            current_user.first_name = data['first_name']
        if 'last_name' in data:
            current_user.last_name = data['last_name']
        if 'email' in data:
            current_user.email = data['email']
        if 'phone' in data:
            current_user.phone = data['phone']
        if 'address' in data:
            current_user.address = data['address']
        if 'username' in data:
            current_user.username = data['username']
        if 'password' in data and data['password']:
            current_user.set_password(data['password'])

        db.session.commit()
        return jsonify({'success': True})

    elif request.method == 'DELETE':
        try:
            # Удаляем все связанные данные пользователя
            Cart.query.filter_by(user_id=current_user.id).delete()

            # Отмечаем заказы как анонимные (или можно удалить)
            orders = Order.query.filter_by(user_id=current_user.id).all()
            for order in orders:
                order.user_id = None  # или db.session.delete(order)

            # Удаляем пользователя
            db.session.delete(current_user)
            db.session.commit()

            logout_user()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/products/search', methods=['GET'])
def search_products():
    search_term = request.args.get('q', '').strip()

    if not search_term:
        products = Product.query.all()
    else:
        # Ищем товары, где название содержит поисковый запрос (регистронезависимо)
        products = Product.query.filter(Product.name.ilike(f'%{search_term}%')).all()

    return jsonify({
        "success": True,
        "products": [product.to_dict() for product in products]
    })


@app.route('/api/products/category/<category_name>', methods=['GET'])
def get_products_by_category(category_name):
    try:
        # Находим категорию по имени
        category = Category.query.filter_by(name=category_name).first()

        if not category:
            return jsonify({"success": False, "error": "Category not found"}), 404

        # Получаем товары этой категории
        products = Product.query.filter_by(category_id=category.id).all()

        return jsonify({
            "success": True,
            "products": [product.to_dict() for product in products]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/products/filtered', methods=['GET'])
def get_filtered_products():
    try:
        # Получаем параметры фильтрации из запроса
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        name_filter = request.args.get('name', '').strip()

        # Начинаем формировать запрос
        query = Product.query

        # Применяем фильтры
        if min_price is not None:
            query = query.filter(Product.price >= min_price)
        if max_price is not None:
            query = query.filter(Product.price <= max_price)
        if name_filter:
            query = query.filter(Product.name.ilike(f'%{name_filter}%'))

        # Получаем отфильтрованные товары
        products = query.order_by(Product.created_at.desc()).all()

        return jsonify({
            "success": True,
            "products": [product.to_dict() for product in products]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/orders', methods=['POST'])
@login_required
def create_order():
    try:
        cart_items = Cart.query.filter_by(user_id=current_user.id).all()

        if not cart_items:
            return jsonify({"success": False, "error": "Корзина пуста"}), 400

        # Проверяем наличие товаров на складе
        for item in cart_items:
            product = Product.query.get(item.product_id)
            if product.stock < item.quantity:
                return jsonify({
                    "success": False,
                    "error": f"Недостаточно товара '{product.name}' на складе"
                }), 400

        # Создаем заказ
        data = request.get_json()
        order = Order(
            user_id=current_user.id,
            total=sum(item.product.price * item.quantity for item in cart_items),
            address=data.get('address', ''),
            phone=data.get('phone', ''),
            status='processing'  # Статус по умолчанию
        )
        db.session.add(order)
        db.session.flush()

        # Создаем элементы заказа и уменьшаем количество товаров
        for item in cart_items:
            product = Product.query.get(item.product_id)
            product.stock -= item.quantity  # Уменьшаем количество на складе

            order_item = OrderItem(
                order_id=order.id,
                product_id=item.product_id,
                quantity=item.quantity,
                price=item.product.price
            )
            db.session.add(order_item)

        # Очищаем корзину
        Cart.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

        return jsonify({"success": True, "order_id": order.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/orders/<int:order_id>/comment', methods=['POST'])
@login_required
def add_order_comment(order_id):
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    order.comments = data.get('comments', '')
    db.session.commit()

    return jsonify({"success": True})

@app.route('/api/orders', methods=['GET'])
@login_required
def get_orders():
    try:
        if current_user.is_admin:
            orders = Order.query.order_by(Order.created_at.desc()).all()
        else:
            orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()

        orders_data = []
        for order in orders:
            order_data = {
                "id": order.id,
                "user_id": order.user_id,
                'username': order.user.username if order.user else 'Гость',  # Добавлена проверка на None
                "created_at": order.created_at.isoformat(),
                "status": order.status,
                "total": order.total,
                "items": []
            }
            for item in order.items:
                product = Product.query.get(item.product_id)
                order_data["items"].append({
                    "product_name": product.name if product else "Товар удалён",
                    "quantity": item.quantity,
                    "price": item.price
                })
            orders_data.append(order_data)

        return jsonify({"success": True, "orders": orders_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    try:
        # Общее количество заказов
        total_orders = Order.query.count()

        # Новые заказы за сегодня
        today = datetime.utcnow().date()
        new_orders = Order.query.filter(
            Order.created_at >= today
        ).count()

        # Общее количество пользователей
        total_users = User.query.count()

        # Общее количество товаров
        total_products = Product.query.count()

        # Статусы заказов
        status_counts = db.session.query(
            Order.status, func.count(Order.id)
        ).group_by(Order.status).all()
        order_statuses = {status: count for status, count in status_counts}

        # Популярные товары (топ 5)
        top_products = db.session.query(
            Product.name,
            func.sum(OrderItem.quantity).label('sales'),
            func.sum(OrderItem.quantity * OrderItem.price).label('revenue')
        ).join(OrderItem, OrderItem.product_id == Product.id
               ).group_by(Product.id
                          ).order_by(func.sum(OrderItem.quantity).desc()
                                     ).limit(5).all()

        # Активность за последние 7 дней
        dates = []
        orders_count = []
        registrations_count = []

        for i in range(7, -1, -1):
            date = today - timedelta(days=i)
            dates.append(date.strftime('%Y-%m-%d'))

            # Заказы за день
            orders = Order.query.filter(
                func.date(Order.created_at) == date
            ).count()
            orders_count.append(orders)

            # Регистрации за день
            registrations = User.query.filter(
                func.date(User.created_at) == date
            ).count()
            registrations_count.append(registrations)

        return jsonify({
            "success": True,
            "total_orders": total_orders,
            "new_orders": new_orders,
            "total_users": total_users,
            "total_products": total_products,
            "order_statuses": order_statuses,
            "top_products": [{
                "name": name,
                "sales": sales,
                "revenue": float(revenue)
            } for name, sales, revenue in top_products],
            "activity": {
                "dates": dates,
                "orders": orders_count,
                "registrations": registrations_count
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/chat/rooms', methods=['GET'])
@login_required
def get_chat_rooms():
    if current_user.is_admin:
        # Для администратора - все активные чаты
        rooms = ChatRoom.query.filter_by(is_active=True).order_by(ChatRoom.created_at.desc()).all()
    else:
        # Для пользователя - только его чаты
        rooms = ChatRoom.query.filter_by(user_id=current_user.id, is_active=True).all()

    return jsonify({
        "success": True,
        "rooms": [{
            "id": room.id,
            "user_id": room.user_id,
            "username": room.user.username,
            "created_at": room.created_at.isoformat(),
            "unread_count": ChatMessage.query.filter_by(room_id=room.id, is_read=False)
            .filter(ChatMessage.sender_id != current_user.id).count()
        } for room in rooms]
    })


@app.route('/api/chat/rooms', methods=['POST'])
@login_required
def create_chat_room():
    if current_user.is_admin:
        return jsonify({"success": False, "error": "Администратор не может создавать чаты"}), 400

    # Проверяем, есть ли уже активный чат у пользователя
    existing_room = ChatRoom.query.filter_by(user_id=current_user.id, is_active=True).first()

    if existing_room:
        return jsonify({
            "success": True,
            "room_id": existing_room.id,
            "message": "У вас уже есть активный чат"
        })

    # Создаем новый чат
    new_room = ChatRoom(user_id=current_user.id)
    db.session.add(new_room)
    db.session.commit()

    return jsonify({
        "success": True,
        "room_id": new_room.id,
        "message": "Чат успешно создан"
    })


@app.route('/api/chat/rooms/<int:room_id>/messages', methods=['GET'])
@login_required
def get_chat_messages(room_id):
    room = ChatRoom.query.get_or_404(room_id)

    # Проверка прав доступа
    if not current_user.is_admin and room.user_id != current_user.id:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    # Помечаем сообщения как прочитанные
    if current_user.is_admin or room.user_id == current_user.id:
        ChatMessage.query.filter_by(room_id=room.id, is_read=False) \
            .filter(ChatMessage.sender_id != current_user.id) \
            .update({"is_read": True})
        db.session.commit()

    messages = ChatMessage.query.filter_by(room_id=room.id).order_by(ChatMessage.timestamp.asc()).all()

    return jsonify({
        "success": True,
        "messages": [{
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_name": msg.sender.username,
            "message": msg.message,
            "timestamp": msg.timestamp.isoformat(),
            "is_admin": msg.sender.is_admin
        } for msg in messages]
    })


@app.route('/api/chat/rooms/<int:room_id>/messages', methods=['POST'])
@login_required
def send_chat_message(room_id):
    room = ChatRoom.query.get_or_404(room_id)

    # Проверка прав доступа
    if not current_user.is_admin and room.user_id != current_user.id:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    data = request.get_json()
    message_text = data.get('message', '').strip()

    if not message_text:
        return jsonify({"success": False, "error": "Сообщение не может быть пустым"}), 400

    # Создаем сообщение
    new_message = ChatMessage(
        room_id=room.id,
        sender_id=current_user.id,
        message=message_text
    )

    db.session.add(new_message)
    db.session.commit()

    # Отправляем уведомление через SocketIO
    socketio.emit('new_message', {
        'room_id': room.id,
        'message': {
            'id': new_message.id,
            'sender_id': new_message.sender_id,
            'sender_name': current_user.username,
            'message': new_message.message,
            'timestamp': new_message.timestamp.isoformat(),
            'is_admin': current_user.is_admin
        }
    }, room=f'room_{room.id}')

    return jsonify({"success": True, "message": "Сообщение отправлено"})


@app.route('/api/chat/rooms/<int:room_id>/close', methods=['POST'])
@login_required
def close_chat_room(room_id):
    room = ChatRoom.query.get_or_404(room_id)

    # Только администратор может закрывать чаты
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Доступ запрещен"}), 403

    room.is_active = False
    db.session.commit()

    return jsonify({"success": True, "message": "Чат закрыт"})


@socketio.on('leave_room')
def handle_leave_room(data):
    room_id = data.get('room_id')
    if room_id:
        leave_room(f'room_{room_id}')


# Добавьте обработчики событий для чата
@socketio.on('join_room')
def handle_join_room(data):
    room_id = data.get('room_id')
    join_room(room_id)
    emit('message', {'msg': f'Пользователь присоединился к комнате {room_id}'}, room=room_id)


@socketio.on('send_message')
def handle_send_message(data):
    room_id = data.get('room_id')
    message = data.get('message')
    sender_id = data.get('sender_id')

    # Сохраняем сообщение в БД
    new_message = ChatMessage(
        room_id=room_id,
        sender_id=sender_id,
        message=message,
        is_admin=False
    )
    db.session.add(new_message)
    db.session.commit()

    # Отправляем сообщение всем в комнате
    emit('new_message', {
        'room_id': room_id,
        'message': new_message.to_dict()
    }, room=room_id)

if __name__ == '__main__':
    socketio.run(app, debug=True)
   # app.run(debug=True)



