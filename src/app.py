import os
import uuid
import sys
import tempfile
from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
import pandas as pd
from argparse import Namespace

# Add the 'src' directory to the Python path to resolve local imports in Vercel.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# We assume your engine is in 'main.py' inside the same 'src' folder
from main import run_engine

# --- Flask Application Configuration ---
# Robust and cross-platform path configuration.
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_template_folder = os.path.join(_project_root, 'src', 'templates')
_data_folder = os.path.join(_project_root, 'data')

app = Flask(__name__, template_folder=_template_folder)

# IMPORTANT: Change this to a real and unique secret key in a production environment.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-insecure')

# --- File Path Configuration ---
# Use the system's temporary directory for uploaded files.
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'wie_uploads')
DEFAULT_RULES_PATH = os.path.join(_data_folder, 'warehouse_rules.xlsx')
DEFAULT_INVENTORY_PATH = os.path.join(_data_folder, 'inventory_report.xlsx')


def get_safe_filepath(filename):
    """Creates a unique filename to avoid collisions."""
    safe_uuid = str(uuid.uuid4())
    _, extension = os.path.splitext(filename)
    return os.path.join(UPLOAD_FOLDER, f"{safe_uuid}{extension}")


@app.route('/download/<filename>')
def download(filename):
    """ Serves the sample files from the designated data folder. """
    return send_from_directory(_data_folder, filename, as_attachment=True)


@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Step 1: Manages file uploads or selection of sample data.
    """
    if request.method == 'POST':
        # Cleanup any previous session data to ensure a fresh start
        session.clear()

        use_sample_inventory = request.form.get('use_sample_inventory') == 'true'
        use_sample_rules = request.form.get('use_sample_rules') == 'true'

        inventory_file = request.files.get('inventory_file')
        rules_file = request.files.get('rules_file')

        inventory_filepath = None
        rules_filepath = None

        try:
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)

            # Determine inventory file path
            if use_sample_inventory:
                inventory_filepath = DEFAULT_INVENTORY_PATH
            elif inventory_file and inventory_file.filename:
                inventory_filepath = get_safe_filepath(inventory_file.filename)
                inventory_file.save(inventory_filepath)
            else:
                return render_template('error.html', error_message="The inventory report is a required file."), 400

            # Determine rules file path
            if use_sample_rules:
                rules_filepath = DEFAULT_RULES_PATH
            elif rules_file and rules_file.filename:
                rules_filepath = get_safe_filepath(rules_file.filename)
                rules_file.save(rules_filepath)
            else:
                rules_filepath = DEFAULT_RULES_PATH # Default if none provided/selected

            session['inventory_filepath'] = inventory_filepath
            session['rules_filepath'] = rules_filepath

            df_headers = pd.read_excel(inventory_filepath, nrows=0)
            session['user_columns'] = df_headers.columns.tolist()

            return redirect(url_for('mapping'))

        except Exception as e:
            print(f"[ERROR] at file upload: {e}")
            error_msg = f"Error processing file. Make sure it is a valid .xlsx file. (Detail: {type(e).__name__})"
            return render_template('error.html', error_message=error_msg), 500

    return render_template('index.html')


@app.route('/mapping', methods=['GET'])
def mapping():
    """
    Step 2: Displays the column mapping page.
    """
    if 'user_columns' not in session or 'inventory_filepath' not in session:
        return redirect(url_for('index'))

    user_columns = session['user_columns']
    return render_template('mapping.html', user_columns=user_columns)


@app.route('/process', methods=['POST'])
def process_mapping():
    """
    Step 3: Processes the mapping, runs the engine, and displays the results.
    """
    try:
        inventory_path = session.get('inventory_filepath')
        rules_path = session.get('rules_filepath') # Get the path of the rules

        if not all([inventory_path, rules_path]):
            return render_template('error.html', error_message="Session expired. Please start over."), 400

        # Create the dictionary to rename columns
        column_mapping = {request.form[key]: key for key in request.form}

        # Load DataFrames
        inventory_df = pd.read_excel(inventory_path)
        inventory_df.rename(columns=column_mapping, inplace=True)
        
        # Ensure the date column is of the correct type
        if 'creation_date' in inventory_df.columns:
            inventory_df['creation_date'] = pd.to_datetime(inventory_df['creation_date'])
        
        rules_df = pd.read_excel(rules_path)
        
        # Configure arguments for the engine
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
        print(f"[ERROR] during processing: {e}")
        error_msg = f"An error occurred while analyzing the data. (Detail: {type(e).__name__})"
        return render_template('error.html', error_message=error_msg), 500
    
    finally:
        # Cleanup of temporary files and session
        for key in ['inventory_filepath', 'rules_filepath', 'user_columns']:
            item = session.pop(key, None)
            # Make sure the item is a file path and that it exists before trying to delete it.
            if isinstance(item, str) and item.startswith(UPLOAD_FOLDER) and os.path.exists(item):
                try:
                    os.remove(item)
                except OSError:
                    # Do nothing if the file does not exist or there is another error
                    pass

# --- Entry Point to Run the Application ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)