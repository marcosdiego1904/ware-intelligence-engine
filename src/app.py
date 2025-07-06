import os
import uuid
from flask import Flask, render_template, request, session, redirect, url_for
import pandas as pd
from argparse import Namespace

# Asumimos que tu motor está en 'main.py' dentro de la misma carpeta 'src'
from main import run_engine

# --- Configuración de la Aplicación Flask ---
app = Flask(__name__)
# IMPORTANTE: Cambia esto por una clave secreta real y única en un entorno de producción.
# Es necesario para que Flask pueda manejar sesiones de forma segura.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-insecure')

# --- Configuración de Rutas de Archivos ---
# SCRIPT_DIR es la ruta a la carpeta actual ('src').
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# UPLOAD_FOLDER es donde guardaremos temporalmente los archivos subidos.
# Usamos /tmp en un entorno serverless como Vercel, ya que es la única carpeta escribible.
UPLOAD_FOLDER = '/tmp/wie_uploads'
# RULES_PATH es la ruta al archivo de reglas por defecto.
# La ruta ahora apunta a un archivo junto a app.py, lo que es mucho más robusto para Vercel.
# ASEGÚRATE de mover 'warehouse_rules.xlsx' a la carpeta 'src'.
RULES_PATH = os.path.join(SCRIPT_DIR, 'warehouse_rules.xlsx')


@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Paso 1: Gestiona la carga inicial del archivo de inventario.
    Si es GET, muestra la página principal.
    Si es POST, guarda el archivo, lee sus encabezados y redirige al mapeo.
    """
    if request.method == 'POST':
        inventory_file = request.files.get('inventory_file')

        # Validación: Asegurarse de que el archivo de inventario fue enviado y tiene nombre.
        if not inventory_file or not inventory_file.filename:
            error_msg = "No se subió el reporte de inventario, que es un archivo requerido."
            return render_template('error.html', error_message=error_msg), 400

        try:
            # Nos aseguramos de que la carpeta de subidas exista justo antes de usarla.
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)

            # Crea un nombre de archivo único para evitar sobreescribir archivos.
            filename = str(uuid.uuid4()) + os.path.splitext(inventory_file.filename)[1]
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            inventory_file.save(filepath)

            # Lee solo la primera fila (encabezados) para el mapeo.
            df_headers = pd.read_excel(filepath, nrows=0)
            user_columns = df_headers.columns.tolist()

            # Guarda la ruta del archivo y los nombres de las columnas en la sesión del usuario.
            session['inventory_filepath'] = filepath
            session['user_columns'] = user_columns

            # Redirige al usuario a la página de mapeo.
            return redirect(url_for('mapping'))

        except Exception as e:
            # Manejo de errores si el archivo no es un Excel válido u otro problema.
            print(f"[ERROR] en la carga inicial: {e}")
            user_error_message = f"Error al leer el archivo. Asegúrate de que sea un .xlsx válido. (Detalle: {type(e).__name__})"
            return render_template('error.html', error_message=user_error_message), 500

    # Si el método es GET, simplemente muestra la página de inicio.
    return render_template('index.html')


@app.route('/mapping', methods=['GET'])
def mapping():
    """
    Paso 2: Muestra la página de mapeo de columnas.
    Recupera los nombres de las columnas del archivo del usuario desde la sesión
    y los pasa a la plantilla para que se muestren en los menús desplegables.
    """
    # Si el usuario llega aquí sin haber subido un archivo, lo redirigimos al inicio.
    if 'user_columns' not in session or 'inventory_filepath' not in session:
        return redirect(url_for('index'))

    user_columns = session['user_columns']
    return render_template('mapping.html', user_columns=user_columns)


@app.route('/process', methods=['POST'])
def process_mapping():
    """
    Paso 3: Procesa el mapeo enviado por el usuario.
    Carga el archivo completo, renombra las columnas según el mapeo,
    ejecuta el motor de análisis y muestra los resultados.
    """
    try:
        filepath = session.get('inventory_filepath')
        # Validación: Comprueba que la ruta del archivo todavía existe en la sesión.
        if not filepath or not os.path.exists(filepath):
            error_msg = "La sesión ha expirado o el archivo original se ha perdido. Por favor, vuelve a empezar."
            return render_template('error.html', error_message=error_msg), 400

        # Crea el diccionario de mapeo a partir del formulario.
        # El formulario envía {'pallet_id': 'Mi_Columna_ID', ...}
        # Pandas necesita {'Mi_Columna_ID': 'pallet_id', ...}
        # Por eso invertimos las claves y los valores.
        column_mapping = {request.form[key]: key for key in request.form}

        # Carga el DataFrame de inventario completo desde el archivo guardado.
        inventory_df = pd.read_excel(filepath)
        
        # ¡La magia ocurre aquí! Renombra las columnas del DataFrame.
        inventory_df.rename(columns=column_mapping, inplace=True)
        
        # --- FIX: Convertir la columna de fecha a datetime ---
        # Este es el paso crucial que faltaba. Sin esto, las operaciones
        # de tiempo en el motor fallarán con un TypeError.
        if 'creation_date' in inventory_df.columns:
            inventory_df['creation_date'] = pd.to_datetime(inventory_df['creation_date'])
        
        # Carga el archivo de reglas (usando el de por defecto).
        rules_df = pd.read_excel(RULES_PATH)
        
        # Crea un objeto 'args' con los valores por defecto para el motor.
        args = Namespace(
            debug=False,
            floating_time=8,
            straggler_ratio=0.85,
            stuck_ratio=0.80,
            stuck_time=6
        )
        
        # ¡Ejecuta el motor con los datos ya limpios y estandarizados!
        anomalies = run_engine(inventory_df, rules_df, args)

        # Muestra la página de resultados.
        return render_template('results.html', results=anomalies)

    except Exception as e:
        # Manejo de errores durante el procesamiento.
        print(f"[ERROR] durante el procesamiento del mapeo: {e}")
        user_error_message = f"Ocurrió un error al procesar el archivo con el mapeo. (Detalle: {type(e).__name__})"
        return render_template('error.html', error_message=user_error_message), 500
    
    finally:
        # Limpieza: Pase lo que pase, intentamos eliminar el archivo temporal y limpiar la sesión.
        filepath = session.pop('inventory_filepath', None)
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        session.pop('user_columns', None)


# --- Punto de Entrada para Ejecutar la Aplicación ---
if __name__ == '__main__':
    # app.run() inicia el servidor de desarrollo de Flask.
    # debug=True activa el modo de depuración para ver errores detallados y recarga automática.
    app.run(debug=True, port=5001)
