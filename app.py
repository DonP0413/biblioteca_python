import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

# --- Configuración Inicial ---
app = Flask(__name__)

# Configuración de la Base de Datos (MySQL)
# CAMBIA 'root' Y 'tu_password' por tus credenciales de MySQL
DB_USER = 'root'
DB_PASS = '1234' 
DB_HOST = 'localhost'
DB_NAME = 'biblioteca_db'
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mi_clave_secreta_muy_dificil' # Cambia esto por algo aleatorio

# Inicializa las extensiones
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Página a la que redirige si no estás logueado
login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'

# --- (M) MODELO (Definición de Datos) ---

# El 'UserMixin' es necesario para Flask-Login
class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuario' # Nombre de la tabla
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # --- LÍNEA NUEVA ---
    # Por defecto, nadie es admin (default=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    # ------------------

    # Relación: Un usuario tiene muchos libros
    libros = db.relationship('Libro', backref='propietario', lazy=True)

    # Métodos para hashear y verificar la contraseña
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    # Relación: Un usuario tiene muchos libros
    libros = db.relationship('Libro', backref='propietario', lazy=True)

    # Métodos para hashear y verificar la contraseña
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Libro(db.Model):
    __tablename__ = 'libro' # Nombre de la tabla
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(200), nullable=False)
    autor = db.Column(db.String(100), nullable=False)
    leido = db.Column(db.Boolean, default=False)
    
    # Clave Foránea: Conecta el libro con el usuario
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

# Función de Flask-Login para cargar un usuario desde la sesión
@login_manager.user_loader
# Función de Flask-Login para cargar un usuario desde la sesión
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# --- CÓDIGO NUEVO: DECORADOR DE ADMIN ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Si el usuario no está logueado, o no es un admin
        if not current_user.is_authenticated or not current_user.is_admin:
            # 'abort(403)' significa "Prohibido"
            abort(403) 
        return f(*args, **kwargs)
    return decorated_function
# ----------------------------------------


# --- (C) CONTROLADOR (Lógica de la Aplicación) ---

# --- Rutas de Autenticación ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('biblioteca')) # Si ya está logueado, va a la biblioteca
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validación
        usuario_existente = Usuario.query.filter_by(username=username).first()
        if usuario_existente:
            flash('Ese nombre de usuario ya existe.', 'danger')
            return redirect(url_for('register'))
            
        # Creación de usuario
        nuevo_usuario = Usuario(username=username)
        nuevo_usuario.set_password(password)
        db.session.add(nuevo_usuario)
        db.session.commit()
        
        flash('¡Cuenta creada! Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html') # (V) Muestra la Vista de registro

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('biblioteca'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        usuario = Usuario.query.filter_by(username=username).first()
        
        # Verificación
        if usuario and usuario.check_password(password):
            login_user(usuario) # Inicia la sesión
            return redirect(url_for('biblioteca'))
        else:
            flash('Login incorrecto. Revisa usuario y contraseña.', 'danger')
            
    return render_template('login.html') # (V) Muestra la Vista de login

@app.route('/logout')
@login_required
def logout():
    logout_user() # Cierra la sesión
    return redirect(url_for('login'))

# --- Rutas CRUD (Biblioteca) ---

@app.route('/')
@login_required # ¡Protegido! Solo usuarios logueados
def biblioteca():
    # (R) READ: Obtiene solo los libros del usuario actual
    libros_del_usuario = Libro.query.filter_by(propietario=current_user).all()
    
    # (V) Muestra la Vista de biblioteca, pasando los datos (libros)
    return render_template('biblioteca.html', libros=libros_del_usuario)

@app.route('/agregar', methods=['POST'])
@login_required
def agregar_libro():
    # (C) CREATE: Crea un nuevo libro
    titulo = request.form['titulo']
    autor = request.form['autor']
    
    nuevo_libro = Libro(titulo=titulo, autor=autor, propietario=current_user) # Asigna el propietario
    db.session.add(nuevo_libro)
    db.session.commit()
    
    flash('¡Libro añadido!', 'success')
    return redirect(url_for('biblioteca'))

@app.route('/actualizar/<int:id_libro>')
@login_required
def actualizar_libro(id_libro):
    # (U) UPDATE: Actualiza el estado 'leido'
    libro = Libro.query.get_or_404(id_libro)
    
    # Seguridad: Verifica que el libro pertenece al usuario actual
    if libro.propietario != current_user:
        flash('No tienes permiso para editar este libro.', 'danger')
        return redirect(url_for('biblioteca'))
        
    libro.leido = not libro.leido # Invierte el estado (True -> False, False -> True)
    db.session.commit()
    
    flash('¡Estado del libro actualizado!', 'success')
    return redirect(url_for('biblioteca'))

@app.route('/borrar/<int:id_libro>')
@login_required
def borrar_libro(id_libro):
    # (D) DELETE: Borra un libro
    libro = Libro.query.get_or_404(id_libro)
    
    # Seguridad: Verifica que el libro pertenece al usuario actual
    if libro.propietario != current_user:
        flash('No tienes permiso para borrar este libro.', 'danger')
        return redirect(url_for('biblioteca'))

    db.session.delete(libro)
    db.session.commit()
    
    flash('¡Libro borrado!', 'success')
    return redirect(url_for('biblioteca'))
# --- Rutas de ADMIN ---

@app.route('/admin')
@login_required  # Primero, debe estar logueado
@admin_required  # Segundo, debe ser admin
def admin_dashboard():
    # El admin puede ver TODOS los usuarios y libros
    todos_los_usuarios = Usuario.query.all()
    todos_los_libros = Libro.query.all()
    return render_template('admin.html', 
                           usuarios=todos_los_usuarios, 
                           libros=todos_los_libros)

@app.route('/admin/delete_user/<int:id_usuario>')
@login_required
@admin_required
def borrar_usuario_admin(id_usuario):
    usuario = Usuario.query.get_or_404(id_usuario)
    if usuario.is_admin:
        flash('No se puede borrar a otro administrador.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Borrar todos los libros de este usuario primero
    Libro.query.filter_by(usuario_id=id_usuario).delete()
    # Ahora borrar el usuario
    db.session.delete(usuario)
    db.session.commit()
    flash(f'Usuario {usuario.username} y todos sus libros han sido borrados.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- Punto de entrada (para ejecutar con 'python app.py') ---
if __name__ == '__main__':
    # Creación de las tablas (solo si no existen)
    with app.app_context():
        db.create_all()
    app.run(debug=True)