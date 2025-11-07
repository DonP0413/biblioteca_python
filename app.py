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
# Configuración de la Base de Datos (MySQL)
# Ahora usamos un usuario con privilegios limitados
DB_USER = 'biblioteca_app'        # <-- El nuevo usuario
DB_PASS = '0000' # <-- El nuevo password que elegiste
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

# --- (M) MODELO (Definición de Datos) ---

# El 'UserMixin' es necesario para Flask-Login
class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuario' # Nombre de la tabla
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    avatar_img = db.Column(db.String(200), nullable=False, default='/static/avatars/default.jpg') # Mantenemos el .jpg

    # --- LÍNEAS NUEVAS ---
    # Guardamos la pregunta y la RESPUESTA HASHEADA
    # Son 'nullable=True' porque el usuario las configura DESPUÉS de registrarse.
    security_question = db.Column(db.String(300), nullable=True)
    security_answer_hash = db.Column(db.String(128), nullable=True)
    # --------------------

    # Relación: Un usuario tiene muchos libros
    libros = db.relationship('Libro', backref='propietario', lazy=True)

    # --- Métodos de Contraseña (YA EXISTEN) ---
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    # --- MÉTODOS NUEVOS (Para la respuesta de seguridad) ---
    def set_security_answer(self, answer):
        # Hasheamos la respuesta de la misma forma que la contraseña
        # Usamos 'str(answer)' para asegurarnos de que sea una cadena
        self.security_answer_hash = bcrypt.generate_password_hash(str(answer)).decode('utf-8')

    def check_security_answer(self, answer):
        # Verificamos la respuesta hasheada
        # Es importante chequear que el hash no esté vacío (None)
        if not self.security_answer_hash:
            return False
        return bcrypt.check_password_hash(self.security_answer_hash, str(answer))

class Libro(db.Model):
    __tablename__ = 'libro'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(200), nullable=False)
    autor = db.Column(db.String(100), nullable=False)
    leido = db.Column(db.Boolean, default=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

    # --- LÍNEAS NUEVAS ---
    # Usamos nullable=False y default=0 para asegurarnos de que siempre tengan un valor.
    paginas_totales = db.Column(db.Integer, nullable=False, default=0)
    pagina_actual = db.Column(db.Integer, nullable=False, default=0)
    # --------------------

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
# --- Rutas de Recuperación de Contraseña ---

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = Usuario.query.filter_by(username=username).first()

        # Validaciones
        if not user:
            flash('No existe un usuario con ese nombre.', 'danger')
            return redirect(url_for('forgot_password'))
        
        if not user.security_question:
            flash('Este usuario no tiene preguntas de seguridad configuradas. No se puede recuperar la cuenta.', 'danger')
            return redirect(url_for('forgot_password'))
        
        # Éxito: redirige al usuario a la página de reseteo
        return redirect(url_for('reset_password', username=user.username))

    return render_template('forgot_password.html')


@app.route('/reset_password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    # Buscamos al usuario o mostramos un error 404 si no existe
    user = Usuario.query.filter_by(username=username).first_or_404()

    if request.method == 'POST':
        # 1. Obtener datos del formulario
        security_answer = request.form['security_answer']
        password_nueva = request.form['password_nueva']
        password_confirm = request.form['password_confirm']

        # 2. Validar la respuesta de seguridad
        if not user.check_security_answer(security_answer):
            flash('Respuesta de seguridad incorrecta.', 'danger')
            return redirect(url_for('reset_password', username=user.username))
        
        # 3. Validar la nueva contraseña
        if not password_nueva or not password_confirm:
            flash('La nueva contraseña no puede estar vacía.', 'danger')
            return redirect(url_for('reset_password', username=user.username))
            
        if password_nueva != password_confirm:
            flash('Las nuevas contraseñas no coinciden.', 'danger')
            return redirect(url_for('reset_password', username=user.username))
        
        # 4. Éxito: Guardar la nueva contraseña
        user.set_password(password_nueva)
        db.session.commit()
        
        flash('¡Contraseña actualizada con éxito! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    # Si es GET, mostramos la página con la pregunta
    return render_template('reset_password.html', 
                           username=user.username, 
                           security_question=user.security_question)

@app.route('/logout')
@login_required
def logout():
    logout_user() # Cierra la sesión
    return redirect(url_for('login'))

# --- Rutas CRUD (Biblioteca) ---

@app.route('/')
@login_required 
def biblioteca():
    # --- Lógica de Búsqueda (NUEVO) ---
    # Obtenemos el término de búsqueda de la URL (ej. /?q=Quijote)
    termino_busqueda = request.args.get('q', '') # 'q' es el nombre del input

    # Empezamos la consulta base
    query_base = Libro.query.filter_by(propietario=current_user)

    # Si hay un término de búsqueda, filtramos la consulta
    if termino_busqueda:
        # Usamos .like() para buscar coincidencias parciales (case-insensitive con 'ilike')
        query_base = query_base.filter(Libro.titulo.ilike(f"%{termino_busqueda}%"))
    
    # Ejecutamos la consulta final
    libros_del_usuario = query_base.all()
    # ------------------------------------

    # Pasamos el término de búsqueda de vuelta a la plantilla
    # para que la barra de búsqueda no se borre.
    return render_template('biblioteca.html', 
                           libros=libros_del_usuario, 
                           termino_busqueda=termino_busqueda)
@app.route('/agregar', methods=['POST'])
@login_required
def agregar_libro():
    if request.method == 'POST':
        titulo = request.form['titulo']
        autor = request.form['autor']
        
        # --- Campo Nuevo ---
        # Obtenemos el total de páginas. Si está vacío, guardamos 0.
        try:
            paginas_totales = int(request.form['paginas_totales'])
            if paginas_totales < 0:
                paginas_totales = 0
        except ValueError:
            paginas_totales = 0
        # -------------------

        if titulo and autor:
            nuevo_libro = Libro(
                titulo=titulo, 
                autor=autor, 
                propietario=current_user,
                paginas_totales=paginas_totales, # Guardamos el valor
                pagina_actual=0                 # Empezamos en la página 0
            )
            db.session.add(nuevo_libro)
            db.session.commit()
            flash('¡Libro añadido con éxito!', 'success')
        else:
            flash('El título y el autor son obligatorios.', 'danger')
            
    return redirect(url_for('biblioteca'))

@app.route('/actualizar_progreso/<int:id_libro>', methods=['GET', 'POST'])
@login_required
def actualizar_progreso(id_libro):
    # Buscamos el libro o damos error 404
    libro = Libro.query.get_or_404(id_libro)

    # Verificamos que el libro pertenezca al usuario actual
    if libro.propietario != current_user:
        flash('No tienes permiso para editar este libro.', 'danger')
        abort(403) # Error de "Prohibido"

    if request.method == 'POST':
        try:
            # Obtenemos la página actual del formulario
            pagina_actual = int(request.form['pagina_actual'])

            # Validaciones
            if pagina_actual < 0:
                pagina_actual = 0
            # Evitamos que ponga una pág actual mayor al total
            if libro.paginas_totales > 0 and pagina_actual > libro.paginas_totales:
                pagina_actual = libro.paginas_totales
            
            # Actualizamos el libro
            libro.pagina_actual = pagina_actual

            # Lógica automática de "Leído"
            if libro.paginas_totales > 0 and libro.pagina_actual == libro.paginas_totales:
                libro.leido = True
            else:
                libro.leido = False # Si regresa páginas, se marca como no leído

            db.session.commit()
            flash('¡Progreso actualizado con éxito!', 'success')
            return redirect(url_for('biblioteca'))

        except ValueError:
            flash('Por favor, introduce un número válido.', 'danger')
            return redirect(url_for('actualizar_progreso', id_libro=id_libro))

    # Si es GET, mostramos la página de actualización
    return render_template('actualizar_progreso.html', libro=libro)

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
# --- Ruta para Editar Perfil ---

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    if request.method == 'POST':
        # --- Banderas para saber qué cambió ---
        changes_made = False
        
        # --- 1. Lógica de Avatar (siempre se actualiza si cambia) ---
        avatar_seleccionado = request.form.get('avatar')
        if avatar_seleccionado and current_user.avatar_img != avatar_seleccionado:
            current_user.avatar_img = avatar_seleccionado
            changes_made = True
            flash('¡Avatar actualizado!', 'success')

        # --- 2. Lógica de Contraseña ---
        pw_actual = request.form.get('password_actual')
        pw_nueva = request.form.get('password_nueva')
        pw_confirm = request.form.get('password_confirm')
        
        # Solo si el usuario rellenó los 3 campos de contraseña
        if pw_actual and pw_nueva and pw_confirm:
            if not current_user.check_password(pw_actual):
                flash('Tu contraseña actual es incorrecta. No se pudo cambiar la contraseña.', 'danger')
            elif pw_actual == pw_nueva:
                flash('La nueva contraseña no puede ser la misma que la actual.', 'danger')
            elif pw_nueva != pw_confirm:
                flash('Las nuevas contraseñas no coinciden.', 'danger')
            else:
                # Éxito en cambio de contraseña
                current_user.set_password(pw_nueva)
                changes_made = True
                flash('¡Contraseña actualizada con éxito!', 'success')
        # Si rellenó solo algunos campos
        elif pw_actual or pw_nueva or pw_confirm:
             flash('Para cambiar la contraseña, debes rellenar los TRES campos de la sección "Cambiar mi Contraseña".', 'warning')
        
        # --- 3. Lógica de Pregunta de Seguridad ---
        sec_q = request.form.get('security_question')
        sec_a = request.form.get('security_answer')
        pw_actual_sec = request.form.get('password_actual_sec')

        # Solo si el usuario rellenó los 3 campos de seguridad
        if sec_q and sec_a and pw_actual_sec:
            if not current_user.check_password(pw_actual_sec):
                flash('Tu contraseña actual es incorrecta. No se pudo cambiar la pregunta de seguridad.', 'danger')
            else:
                # Éxito en cambio de pregunta
                current_user.security_question = sec_q
                current_user.set_security_answer(sec_a)
                changes_made = True
                flash('¡Pregunta de seguridad actualizada con éxito!', 'success')
        # Si rellenó solo algunos campos
        elif sec_q or sec_a or pw_actual_sec:
             flash('Para configurar la pregunta de seguridad, debes rellenar los TRES campos de la sección "Pregunta de Seguridad".', 'warning')
        
        # --- 4. Guardar cambios si se hizo alguno ---
        if changes_made:
            db.session.commit()
        
        return redirect(url_for('perfil'))

    

    # Si es un método GET, solo mostramos la página
    return render_template('perfil.html')

    
# --- Punto de entrada (para ejecutar con 'python app.py') ---
if __name__ == '__main__':
    # Creación de las tablas (solo si no existen)
    with app.app_context():
        db.create_all()
    app.run(debug=True)