import os
from flask import Flask, render_template, request
import pandas as pd
from argparse import Namespace

# Asumimos que tu motor está en 'engine.py' dentro de la misma carpeta 'src'
from main import run_engine

# --- Configuración de la Aplicación Flask ---
app = Flask(__name__)

# --- Configuración de Rutas de Archivos ---
# Esto hace que la aplicación sea robusta y encuentre siempre el archivo de reglas por defecto.
# SCRIPT_DIR es la ruta a la carpeta actual ('src').
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# RULES_PATH es la ruta al archivo subiendo un nivel ('..') y entrando en 'data'.
RULES_PATH = os.path.join(SCRIPT_DIR, '..', 'data', 'warehouse_rules.xlsx')


# --- Ruta Principal de la Aplicación ---
@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Gestiona tanto la visualización inicial de la página (GET) como el
    procesamiento de los archivos subidos (POST).
    """
    
    # --- Lógica para cuando el usuario envía el formulario (POST) ---
    if request.method == 'POST':
        # Obtiene los archivos del formulario de manera segura
        inventory_file = request.files.get('inventory_file')
        rules_file = request.files.get('rules_file')

        # Validación: Asegurarse de que el archivo principal fue enviado
        if not inventory_file:
            error_msg = "No se subió el reporte de inventario, que es un archivo requerido."
            return render_template('error.html', error_message=error_msg), 400

        try:
            # --- Carga de Archivos y Ejecución del Motor ---
            
            # Carga el DataFrame de inventario desde el archivo subido
            inventory_df = pd.read_excel(inventory_file)
            
            # Lógica para el archivo de reglas: usa el subido o el de por defecto
            if rules_file:
                # Si el usuario proporcionó un archivo de reglas, úsalo
                rules_df = pd.read_excel(rules_file)
            else:
                # Si no, carga el archivo de reglas por defecto del servidor
                rules_df = pd.read_excel(RULES_PATH)
            
            # Crea un objeto 'args' con los valores por defecto para el motor.
            args = Namespace(
                debug=False,
                floating_time=8,
                straggler_ratio=0.85,
                stuck_ratio=0.80,
                stuck_time=6
            )
            # ¡Ejecuta el motor con los datos listos!
            anomalies = run_engine(inventory_df, rules_df, args)

            # Si todo va bien, muestra la página de resultados
            return render_template('results.html', results=anomalies)

        except Exception as e:
            # --- Manejo de Errores ---
            # Si cualquier cosa falla en el bloque 'try', se ejecuta esto.
            # Imprime el error en la consola del servidor para tu propio registro
            print(f"[ERROR] Ha ocurrido una excepción: {e}") 
            
            # Crea un mensaje de error amigable para el usuario
            user_error_message = f"Error al procesar los archivos. Revisa que los formatos y las columnas sean correctos. (Detalle técnico: {type(e).__name__})"
            
            # Muestra la página de error
            return render_template('error.html', error_message=user_error_message), 500

    # --- Lógica para la primera visita a la página (GET) ---
    # Si el método no es POST, simplemente muestra la página de carga de archivos.
    return render_template('index.html')


# --- Punto de Entrada para Ejecutar la Aplicación ---
if __name__ == '__main__':
    # app.run() inicia el servidor de desarrollo de Flask.
    # debug=True activa el modo de depuración para ver errores y recarga automática.
    app.run(debug=True)