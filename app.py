from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Konfigurasi Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Konfigurasi database
db = mysql.connector.connect(
    host="localhost",
    user="wennnn",
    password="12345",
    database="mydatabase"
)
cursor = db.cursor()

# Model User
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        
        if user:
            login_user(User(user[0]))  # user[0] adalah ID pengguna
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/')
@login_required
def index():
    cursor.execute("SELECT * FROM items")
    items = cursor.fetchall()
    return render_template('index.html', items=items)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        name = request.form['name']
        cursor.execute("INSERT INTO items (name) VALUES (%s)", (name,))
        db.commit()
        return redirect('/')
    return render_template('add.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    if request.method == 'POST':
        name = request.form['name']
        cursor.execute("UPDATE items SET name = %s WHERE id = %s", (name, id))
        db.commit()
        return redirect('/')
    
    cursor.execute("SELECT * FROM items WHERE id = %s", (id,))
    item = cursor.fetchone()
    return render_template('edit.html', item=item)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    cursor.execute("DELETE FROM items WHERE id = %s", (id,))
    db.commit()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
