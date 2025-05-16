from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    type = db.Column(db.String(10), nullable=False)  # 'income' or 'expense'
    recurring = db.Column(db.Boolean, default=False)
    receipt_path = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('signup'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent transactions
    transactions = Transaction.query.filter_by(user_id=current_user.id)\
                          .order_by(Transaction.date.desc())\
                          .limit(5).all()
    
    # Calculate totals
    total_income = sum(t.amount for t in Transaction.query.filter_by(
        user_id=current_user.id, type='income').all())
    total_expense = sum(t.amount for t in Transaction.query.filter_by(
        user_id=current_user.id, type='expense').all())
    balance = total_income - total_expense
    
    return render_template('dashboard.html', 
                         transactions=transactions,
                         total_income=total_income,
                         total_expense=total_expense,
                         balance=balance)

@app.route('/add_income', methods=['GET', 'POST'])
@login_required
def add_income():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        description = request.form.get('description', '')
        recurring = 'recurring' in request.form
        
        new_income = Transaction(
            user_id=current_user.id,
            amount=amount,
            category=category,
            description=description,
            type='income',
            recurring=recurring
        )
        
        db.session.add(new_income)
        db.session.commit()
        
        flash('Income added successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('add_income.html')

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        description = request.form.get('description', '')
        recurring = 'recurring' in request.form
        
        new_expense = Transaction(
            user_id=current_user.id,
            amount=amount,
            category=category,
            description=description,
            type='expense',
            recurring=recurring
        )
        
        db.session.add(new_expense)
        db.session.commit()
        
        flash('Expense added successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('add_expense.html')

@app.route('/add_recurring', methods=['GET', 'POST'])
@login_required
def add_recurring():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        description = request.form.get('description', '')
        transaction_type = request.form['type']
        
        new_recurring = Transaction(
            user_id=current_user.id,
            amount=amount,
            category=category,
            description=description,
            type=transaction_type,
            recurring=True
        )
        
        db.session.add(new_recurring)
        db.session.commit()
        
        flash('Recurring transaction added successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('add_recurring.html')

@app.route('/upload_receipt/<int:transaction_id>', methods=['POST'])
@login_required
def upload_receipt(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    
    if 'receipt' in request.files:
        receipt = request.files['receipt']
        if receipt.filename != '':
            # Create uploads directory if it doesn't exist
            if not os.path.exists('static/uploads'):
                os.makedirs('static/uploads')
            
            # Save the file
            filename = f"receipt_{transaction_id}_{receipt.filename}"
            filepath = os.path.join('static', 'uploads', filename)
            receipt.save(filepath)
            
            # Update transaction with receipt path
            transaction.receipt_path = filepath
            db.session.commit()
            
            flash('Receipt uploaded successfully!')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)