📚 Biblioteca Personal (Proyecto MVC con Flask)

Una aplicación web simple para gestionar una colección personal de libros, construida con Python, Flask y MySQL. Este proyecto demuestra la implementación de la arquitectura MVC (Modelo-Vista-Controlador), autenticación de usuarios, roles (usuario y administrador) y operaciones CRUD completas.

✨ Características Principales

    Autenticación de Usuarios: Sistema completo de Registro, Inicio de Sesión y Cierre de Sesión.

    Roles y Permisos:

        Usuario Estándar: Solo puede ver y gestionar (CRUD) sus propios libros.

        Administrador: Puede ver un panel de control con todos los usuarios y libros del sistema, y tiene permisos para eliminar usuarios.

    Operaciones CRUD:

        Create: Añadir nuevos libros a la colección.

        Read: Ver la lista de libros personales.

        Update: Marcar libros como "leídos" o "no leídos".

        Delete: Eliminar libros de la colección.

    Seguridad:

        Contraseñas hasheadas de forma segura usando Bcrypt.

        Rutas protegidas que requieren inicio de sesión.

        Rutas de administrador protegidas que requieren un rol de "admin".

🛠️ Stack Tecnológico y Arquitectura

    Backend: Python

    Framework: Flask

    Base de Datos: MySQL

    ORM (Mapeo Objeto-Relacional): Flask-SQLAlchemy

    Gestión de Sesiones: Flask-Login

    Hashing de Contraseñas: Flask-Bcrypt

    Driver de MySQL: PyMySQL

    Arquitectura Principal: MVC (Modelo-Vista-Controlador)

        Modelo (M): Las clases Usuario y Libro en app.py que definen la estructura de la base de datos.

        Vista (V): Todos los archivos HTML dentro de la carpeta templates/.

        Controlador (C): Las funciones con decoradores @app.route en app.py que manejan la lógica de negocio.

🚀 Instalación y Puesta en Marcha

Sigue estos pasos para ejecutar el proyecto localmente.

1. Prerrequisitos

    Tener Python 3 instalado.

    Tener un servidor MySQL instalado y ejecutándose.

2. Clonar el Repositorio

Bash

git clone https://github.com/TU_USUARIO/TU_REPO.git
cd TU_REPO

(Reemplaza la URL con la de tu propio repositorio)

3. Configurar la Base de Datos

Asegúrate de que tu servidor MySQL esté corriendo. Conéctate y ejecuta el siguiente comando para crear la base de datos vacía:
SQL

CREATE DATABASE biblioteca_db;

4. Crear y Activar el Entorno Virtual

Bash

# Crear el venv
python -m venv venv

# Activar en Windows (PowerShell)
.\venv\Scripts\activate

# Activar en macOS/Linux
source venv/bin/activate

5. Instalar Dependencias

Se recomienda crear primero un archivo requirements.txt si no lo tienes.
Bash

# (Opcional) Congelar tus dependencias actuales
pip freeze > requirements.txt

# Instalar las dependencias
pip install -r requirements.txt

(Si no tienes un requirements.txt, puedes instalar los paquetes manualmente): pip install Flask Flask-SQLAlchemy PyMySQL Flask-Login Flask-Bcrypt

6. Configurar la Conexión

Abre el archivo app.py y modifica las siguientes líneas con tus credenciales de MySQL:
Python

# (Alrededor de la línea 17)
DB_USER = 'tu_usuario_mysql'
DB_PASS = 'tu_password_mysql'

7. Ejecutar la Aplicación

Bash

python app.py

La aplicación se estará ejecutando en http://127.0.0.1:5000. La primera vez que se ejecute, creará automáticamente las tablas usuario y libro en tu base de datos.

8. Crear el Usuario Administrador (¡Importante!)

El sistema no tiene una forma pública de registrarse como admin. Debes "promover" a un usuario manualmente.

    Ve a http://127.0.0.1:5000/register y registra un nuevo usuario (ej. admin).

    Detén el servidor (Ctrl+C).

    Conéctate a tu base de datos MySQL y ejecuta la siguiente consulta SQL:
    SQL

UPDATE usuario SET is_admin = 1 WHERE username = 'admin';
COMMIT;

¡Listo! Vuelve a ejecutar python app.py. Inicia sesión como admin y ahora verás el panel de administrador.
