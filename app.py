from flask import Flask, render_template, request, redirect, url_for, flash , session , Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import re
from datetime import datetime
import PyPDF2
import pytesseract
from PIL import Image
import traceback
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
import matplotlib.pyplot as plt
import io
import base64
from flask import render_template
import sqlite3
from collections import defaultdict

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///budget.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
# From extract_transactions_from_pdf
pattern = r'(\d{2}[\/\-]\d{2}[\/\-]\d{4})\s+(.*?)\s+(-?\d+[\d,]*\.\d{2})'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

graph_bp = Blueprint('graph', __name__)

# Add allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100))
    date = db.Column(db.String(20))
    description = db.Column(db.String(200))
    amount = db.Column(db.Float)
    category = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Initialize database
with app.app_context():
    db.create_all()


def extract_transactions_from_pdf(pdf_path):
    transactions = []
    
    try:
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            
            for page in reader.pages:
                text = page.extract_text()
                print(f"Raw PDF Text:\n{text}\n{'-'*50}")

                # First check if it's a receipt-style document
                receipt_transactions = process_receipt_text(text)
                if receipt_transactions:
                    transactions.extend(receipt_transactions)
                    continue  # Skip regular processing if receipt found

                # Regular bank statement processing
                statement_pattern = r'(\d{2}[\/\-]\d{2}[\/\-]\d{4})\s+(.*?)\s+(-?\d+[\d,]*\.\d{2})'
                matches = re.findall(statement_pattern, text)
                print(f"Found {len(matches)} bank transactions")

                for date, desc, amount in matches:
                    try:
                        # Handle different date formats
                        date_formats = ['%d/%m/%Y', '%m/%d/%Y', '%d-%m-%Y']
                        parsed_date = None
                        for fmt in date_formats:
                            try:
                                parsed_date = datetime.strptime(date, fmt)
                                break
                            except ValueError:
                                continue

                        if not parsed_date:
                            continue

                        amount = float(amount.replace(',', ''))
                        
                        transactions.append({
                            'date': parsed_date.strftime('%Y-%m-%d'),
                            'description': desc.strip(),
                            'amount': abs(amount)
                        })
                    except Exception as e:
                        print(f"Error processing transaction: {str(e)}")
                        continue

    except Exception as e:
        print(f"PDF processing error: {str(e)}")
    
    return transactions

def process_receipt_text(text):
    transactions = []
    
    # Try to find receipt header
    if "RECEIPT" not in text and "TOTAL AMOUNT" not in text:
        return []
    
    print("Processing receipt-style document")
    
    try:
        # Extract date
        date_match = re.search(r'\d{2}-\d{2}-\d{4}', text)
        trans_date = datetime.now().strftime('%Y-%m-%d')
        if date_match:
            try:
                trans_date = datetime.strptime(date_match.group(), '%d-%m-%Y').strftime('%Y-%m-%d')
            except:
                pass

        # Extract total amount
        total_match = re.search(r'TOTAL\s+AMOUNT\s+\D*(\d+\.\d{2})', text, re.IGNORECASE)
        if total_match:
            transactions.append({
                'date': trans_date,
                'description': 'Retail Purchase',
                'amount': float(total_match.group(1))
            })
            print(f"Found receipt total: {transactions[-1]}")

        # Alternative: Extract individual items
        item_matches = re.findall(r'(\d+ x .+?)\s+(\$\d+\.\d{2})', text)
        for item, price in item_matches:
            transactions.append({
                'date': trans_date,
                'description': item.strip(),
                'amount': float(price.replace('$', ''))
            })

    except Exception as e:
        print(f"Receipt processing error: {str(e)}")
    
    return transactions

def categorize_transaction(description):
    desc = description.lower()
    categories = {
        'Food': ['swiggy', 'zomato', 'grocery', 'restaurant', 'food'],
        'Travel': ['ola', 'uber', 'fuel', 'metro', 'flight'],
        'Education': ['coursera', 'udemy', 'school', 'book', 'tuition']
    }
    for category, keywords in categories.items():
        if any(keyword in desc for keyword in keywords):
            return category
    return 'Miscellaneous'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_image(image_path):
    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return extract_transactions_from_receipt(text)
    except Exception as e:
        print(f"OCR Error: {str(e)}")
        return []
        # Extract transaction details
        transaction = {
            'date': re.search(r'\d{2}/\d{2}/\d{4}', text).group(0),
            'description': re.search(r'[A-Za-z\s]+', text).group(0).strip(),
            'amount': float(re.search(r'\d+\.\d{2}', text).group(0))
        }
        return transaction
    except Exception as e:
        print(f"OCR Error: {str(e)}")
        return None



def extract_transactions_from_receipt(text):
    total_amount = None
    # Regex pattern to find total amount
    total_pattern = r'TOTAL\s+AMOUNT\s+\D*(\d+\.\d{2})'
    match = re.search(total_pattern, text, re.IGNORECASE)
    
    if match:
        total_amount = float(match.group(1))
        return [{
            'date': datetime.now().strftime('%Y-%m-%d'),  # Use current date or extract from receipt
            'description': 'Shopping Purchase',
            'amount': total_amount
        }]
    return []

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('signup'))
            
        new_user = User(
            email=email,
            password=generate_password_hash(password)  # Removed method parameter
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Main application routes
@app.route('/dashboard')
@login_required
def dashboard():
    categories = ['Food', 'Travel', 'Education', 'Miscellaneous']
    totals = {}
    for category in categories:
        totals[category] = db.session.query(db.func.sum(Transaction.amount)).\
            filter(Transaction.user_id == current_user.id, 
                   Transaction.category == category).scalar() or 0.0
    
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    return render_template('dashboard.html', totals=totals, transactions=transactions)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        try:
            # Check if file was uploaded
            if 'file' not in request.files:
                flash('No file selected', 'error')
                return redirect(request.url)
            
            file = request.files['file']
            
            # Validate file presence and extension
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(request.url)
            
            if not file.filename.lower().endswith('.pdf'):
                flash('Only PDF files are allowed', 'error')
                return redirect(request.url)
            
            # Secure filename and save
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)
            print(f"\n📁 File saved to: {save_path}")

            # Extract transactions
            transactions = extract_transactions_from_pdf(save_path)
            print(f"\n🔍 Found {len(transactions)} raw transactions")
            
            if not transactions:
                flash('No transactions found in PDF', 'warning')
                return redirect(request.url)
            
            # Process and save transactions
            new_transactions = []
            for idx, transaction in enumerate(transactions):
                try:
                    category = categorize_transaction(transaction['description'])
                    print(f"\n⚙️ Processing transaction {idx + 1}:")
                    print(f"   Date: {transaction['date']}")
                    print(f"   Desc: {transaction['description']}")
                    print(f"   Amt:  {transaction['amount']}")
                    print(f"   Cat:  {category}")

                    new_trans = Transaction(
                        user_id=current_user.id,
                        date=transaction['date'],
                        description=transaction['description'],
                        amount=transaction['amount'],
                        category=category
                    )
                    db.session.add(new_trans)
                    new_transactions.append(new_trans)
                
                except Exception as e:
                    print(f"\n❌ Error processing transaction {idx}: {str(e)}")
                    continue

            # Commit to database
            db.session.commit()
            print(f"\n💾 Successfully saved {len(new_transactions)} transactions")
            flash(f'Successfully processed {len(new_transactions)} transactions!', 'success')
            
            # Cleanup uploaded file (optional)
            # os.remove(save_path)
            
            return redirect(url_for('dashboard'))

        except PyPDF2.errors.PdfReadError:
            flash('Invalid PDF file - could not read contents', 'error')
            return redirect(request.url)
        
        except Exception as e:
            db.session.rollback()
            print(f"\n🔥 Critical error: {traceback.format_exc()}")
            flash(f'Error processing file: {str(e)}', 'error')
            return redirect(request.url)
    
    # GET request - show upload form
    return render_template('upload.html')


@app.route('/upload_image', methods=['GET', 'POST'])
@login_required
def upload_image():
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No image file provided', 'error')
            return redirect(request.url)

        image = request.files['image']
        if image.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if image:
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)

            # OCR using Tesseract
            text = pytesseract.image_to_string(Image.open(image_path))

            # Extract total amount (e.g., TOTAL AMOUNT $363.99 or TOTAL AMOUNT    $363.99)
            match = re.search(r'TOTAL AMOUNT\s*\$?([\d,]+\.\d{2})', text, re.IGNORECASE)
            if match:
                amount_str = match.group(1).replace(',', '')
                try:
                    amount = float(amount_str)
                    session['pending_transaction'] = {
                        'filename': filename,
                        'date': datetime.now().strftime('%d/%m/%Y'),
                        'description': 'Receipt OCR Total',
                        'amount': amount
                    }
                    return redirect(url_for('categorize'))
                except ValueError:
                    flash('Failed to parse amount from receipt.', 'error')
                    return redirect(request.url)
            else:
                flash('No total amount found in receipt.', 'error')
                return redirect(request.url)

    return render_template('upload_image.html')


@app.route('/categorize', methods=['GET', 'POST'])
@login_required
def categorize():
    if 'pending_transaction' not in session:
        return redirect(url_for('upload_image'))
    
    transaction = session['pending_transaction']
    
    if request.method == 'POST':
        try:
            # Update with user input
            transaction['category'] = request.form['category']
            transaction['amount'] = float(request.form['amount'])
            transaction['date'] = request.form['date']
            transaction['description'] = request.form['description']
            
            # Save to database
            new_trans = Transaction(
                user_id=current_user.id,
                date=transaction['date'],
                description=transaction['description'],
                amount=transaction['amount'],
                category=transaction['category']
            )
            db.session.add(new_trans)
            db.session.commit()
            
            session.pop('pending_transaction', None)
            flash('Transaction saved!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            print(f"Error saving transaction: {str(e)}")
            flash('Error saving transaction', 'error')
    
    return render_template('categorize.html', transaction=transaction)

@app.route('/categorize_multiple', methods=['GET', 'POST'])
@login_required
def categorize_multiple():
    if 'pending_transactions' not in session or not session['pending_transactions']:
        return redirect(url_for('upload_image'))

    # Get the first transaction from the list
    transaction = session['pending_transactions'][0]

    if request.method == 'POST':
        try:
            transaction['category'] = request.form['category']
            transaction['amount'] = float(request.form['amount'])
            transaction['date'] = request.form['date']
            transaction['description'] = request.form['description']

            # Save to DB
            new_trans = Transaction(
                user_id=current_user.id,
                date=transaction['date'],
                description=transaction['description'],
                amount=transaction['amount'],
                category=transaction['category']
            )
            db.session.add(new_trans)
            db.session.commit()

            # Remove the processed one
            session['pending_transactions'].pop(0)

            if not session['pending_transactions']:
                session.pop('pending_transactions', None)
                flash('All transactions saved!', 'success')
                return redirect(url_for('dashboard'))

            return redirect(url_for('categorize_multiple'))

        except Exception as e:
            db.session.rollback()
            flash('Error saving transaction', 'error')

    return render_template('categorize.html', transaction=transaction)



@app.route('/graph')
@login_required
def show_graph():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()

    from collections import defaultdict
    category_totals = defaultdict(float)
    total_expense = 0.0

    for txn in transactions:
        category_totals[txn.category] += txn.amount
        total_expense += txn.amount

    categories = list(category_totals.keys())
    amounts = list(category_totals.values())

    return render_template(
        'graph.html',
        categories=categories,
        amounts=amounts,
        total_expense=round(total_expense, 2)
    )



if __name__ == '__main__':
    app.run(debug=True)
