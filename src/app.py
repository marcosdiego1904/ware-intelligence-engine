import os
import uuid
import sys
from flask import Flask, render_template, request, session, redirect, url_for
import pandas as pd
from argparse import Namespace

# Añadir el directorio 'src' a la ruta de Python para resolver importaciones locales en Vercel.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Asumimos que tu motor está en 'main.py' dentro de la misma carpeta 'src'
from main import run_engine

# --- Configuración de la Aplicación Flask ---
app = Flask(__name__)
# IMPORTANTE: Cambia esto por una clave secreta real y única en un entorno de producción.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-insecure')

# --- Configuración de Rutas de Archivos ---
# En un entorno serverless, /tmp es la única carpeta escribible.
UPLOAD_FOLDER = '/tmp/wie_uploads'
# Se construye una ruta robusta al archivo de reglas por defecto para evitar
# problemas con el directorio de trabajo actual (CWD) en Vercel.
_base_dir = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES_PATH = os.path.abspath(os.path.join(_base_dir, '..', 'data', 'warehouse_rules.xlsx'))


def get_safe_filepath(filename):
    """Crea un nombre de archivo único para evitar colisiones."""
    safe_uuid = str(uuid.uuid4())
    _, extension = os.path.splitext(filename)
    return os.path.join(UPLOAD_FOLDER, f"{safe_uuid}{extension}")


@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Paso 1: Gestiona la carga de archivos.
    """
    if request.method == 'POST':
        inventory_file = request.files.get('inventory_file')
        rules_file = request.files.get('rules_file') # Archivo de reglas opcional

        if not inventory_file or not inventory_file.filename:
            return render_template('error.html', error_message="El reporte de inventario es un archivo requerido."), 400

        try:
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)

            # Guardar el archivo de inventario (requerido)
            inventory_filepath = get_safe_filepath(inventory_file.filename)
            inventory_file.save(inventory_filepath)
            session['inventory_filepath'] = inventory_filepath

            # Guardar el archivo de reglas (opcional)
            if rules_file and rules_file.filename:
                rules_filepath = get_safe_filepath(rules_file.filename)
                rules_file.save(rules_filepath)
                session['rules_filepath'] = rules_filepath
            else:
                # Si no se sube, usamos la ruta al archivo por defecto
                session['rules_filepath'] = DEFAULT_RULES_PATH

            df_headers = pd.read_excel(inventory_filepath, nrows=0)
            session['user_columns'] = df_headers.columns.tolist()

            return redirect(url_for('mapping'))

        except Exception as e:
            print(f"[ERROR] en la carga de archivos: {e}")
            error_msg = f"Error al procesar el archivo. Asegúrate de que sea un .xlsx válido. (Detalle: {type(e).__name__})"
            return render_template('error.html', error_message=error_msg), 500

    return render_template('index.html')


@app.route('/mapping', methods=['GET'])
def mapping():
    """
    Paso 2: Muestra la página de mapeo de columnas.
    """
    if 'user_columns' not in session or 'inventory_filepath' not in session:
        return redirect(url_for('index'))

    user_columns = session['user_columns']
    return render_template('mapping.html', user_columns=user_columns)


@app.route('/process', methods=['POST'])
def process_mapping():
    """
    Paso 3: Procesa el mapeo, ejecuta el motor y muestra los resultados.
    """
    try:
        inventory_path = session.get('inventory_filepath')
        rules_path = session.get('rules_filepath') # Obtener la ruta de las reglas

        if not all([inventory_path, rules_path]):
            return render_template('error.html', error_message="La sesión expiró. Por favor, vuelve a empezar."), 400

        # Crear el diccionario para renombrar columnas
        column_mapping = {request.form[key]: key for key in request.form}

        # Cargar DataFrames
        inventory_df = pd.read_excel(inventory_path)
        inventory_df.rename(columns=column_mapping, inplace=True)
        
        # Asegurar que la columna de fecha es del tipo correcto
        if 'creation_date' in inventory_df.columns:
            inventory_df['creation_date'] = pd.to_datetime(inventory_df['creation_date'])
        
        rules_df = pd.read_excel(rules_path)
        
        # Configurar argumentos para el motor
        args = Namespace(
            debug=False,
            floating_time=8,
            straggler_ratio=0.85,
            stuck_ratio=0.80,
            stuck_time=6
        )
        
        anomalies = run_engine(inventory_df, rules_df, args)

        return render_template('results.html', results=anomalies)

    except Exception as e:
        print(f"[ERROR] durante el procesamiento: {e}")
        error_msg = f"Ocurrió un error al analizar los datos. (Detalle: {type(e).__name__})"
        return render_template('error.html', error_message=error_msg), 500
    
    finally:
        # Limpieza de archivos temporales y sesión
        for key in ['inventory_filepath', 'rules_filepath', 'user_columns']:
            item = session.pop(key, None)
            # Asegurarse de que el item es una cadena (ruta de archivo) antes de intentar borrarlo
            if isinstance(item, str) and item.startswith('/tmp/'):
                try:
                    os.remove(item)
                except OSError:
                    # No hacer nada si el archivo no existe o hay otro error
                    pass

# --- Punto de Entrada para Ejecutar la Aplicación ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)