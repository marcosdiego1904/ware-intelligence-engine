import os
import uuid
import sys
import tempfile
import json
from datetime import datetime
from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory, flash, jsonify 
import pandas as pd
from argparse import Namespace
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

# Add the 'src' directory to the Python path to resolve local imports in Vercel.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# We assume your engine is in 'main.py' inside the same 'src' folder
from main import run_engine, summarize_anomalies_by_location
from connectors import SQLConnector, APIConnector

# --- Cryptography Setup ---
# IMPORTANT: This key must be securely generated and stored.
# For development, we'll use a fixed key. In production, use environment variables.
# To generate a new key: from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())
ENCRYPTION_KEY = os.environ.get('WIE_ENCRYPTION_KEY', 'b_pKY-s-uJg_jR_ScttWk4s_iUklLde4oar3aA4sI-E=')
if not ENCRYPTION_KEY:
    raise ValueError("No encryption key found. Set the WIE_ENCRYPTION_KEY environment variable.")
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

def encrypt_data(data: str) -> str:
    """Encrypts a string and returns it as a string."""
    if not isinstance(data, str):
        raise TypeError("Data to encrypt must be a string.")
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypts a string and returns it as a string."""
    if not isinstance(encrypted_data, str):
        raise TypeError("Encrypted data must be a string.")
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

# --- Flask Application Configuration ---
# Robust and cross-platform path configuration.
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_template_folder = os.path.join(_project_root, 'src', 'templates')
_data_folder = os.path.join(_project_root, 'data')

app = Flask(__name__, template_folder=_template_folder)

# Database and Login Manager Configuration
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-insecure')

# Environment-aware configuration for database and uploads
IS_VERCEL = os.environ.get('VERCEL') == '1'

if IS_VERCEL:
    # Vercel environment: use the /tmp directory for the database
    db_path = os.path.join('/tmp', 'database.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
else:
    # Local environment: use the instance folder
    instance_path = os.path.join(_project_root, 'instance')
    os.makedirs(instance_path, exist_ok=True)
    db_path = os.path.join(instance_path, 'database.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login' # type: ignore


# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    reports = db.relationship('AnalysisReport', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class DataSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'mysql', 'api', etc.
    
    # Stores the encrypted JSON string of credentials
    encrypted_credentials = db.Column(db.Text, nullable=False)

    user = db.relationship('User', backref=db.backref('data_sources', lazy=True))

    def __init__(self, user_id, name, type):
        self.user_id = user_id
        self.name = name
        self.type = type

    @property
    def credentials(self):
        """Returns the decrypted credentials as a dictionary."""
        decrypted_json = decrypt_data(self.encrypted_credentials)
        return json.loads(decrypted_json)

    @credentials.setter
    def credentials(self, value):
        """Encrypts and stores the credentials dictionary."""
        credentials_json = json.dumps(value)
        self.encrypted_credentials = encrypt_data(credentials_json)


class AnalysisReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_name = db.Column(db.String(120), nullable=False, default=f"Analysis Report")
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    anomalies = db.relationship('Anomaly', backref='report', lazy=True, cascade="all, delete-orphan")
    location_summary = db.Column(db.Text, nullable=True) # Stores a JSON string of the location summary

    def __init__(self, report_name, user_id):
        self.report_name = report_name
        self.user_id = user_id

class Anomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True) # Could store JSON or other details
    report_id = db.Column(db.Integer, db.ForeignKey('analysis_report.id'), nullable=False)
    resolved = db.Column(db.Boolean, default=False, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)

    # --- NEW FIELDS to store structured data ---
    pallet_id = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    anomaly_type = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(50), nullable=False)

    def __init__(self, description, details, report_id, pallet_id=None, location=None, anomaly_type='Unknown', priority='LOW'):
        self.description = description
        self.details = details
        self.report_id = report_id
        self.pallet_id = pallet_id
        self.location = location
        self.anomaly_type = anomaly_type
        self.priority = priority

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# IMPORTANT: Change this to a real and unique secret key in a production environment.
# app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-insecure') # This line is removed as per the new_code

# --- Initialize Database ---
# This replaces the deprecated @before_first_request
with app.app_context():
    db.create_all()

# --- Authentication Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.', 'warning')
            return redirect(url_for('register'))
        
        new_user = User()
        new_user.username = username
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/connections', methods=['GET'])
@login_required
def connections():
    """
    Displays the page for managing database connections.
    """
    user_connections = DataSource.query.filter_by(user_id=current_user.id).order_by(DataSource.name).all()
    return render_template('connections.html', connections=user_connections)


@app.route('/connections/create', methods=['POST'])
@login_required
def create_connection():
    """
    Processes the form for creating a new data source connection,
    handling both MySQL and API types.
    """
    try:
        # 1. Extract common data and connection type
        name = request.form['name'].strip()
        conn_type = request.form['type'].strip()

        # 2. Prepare credential and mapping dictionaries based on type
        credentials = {}
        if conn_type == 'mysql':
            credentials = {
                'db_config': {
                    'host': request.form['host'].strip(),
                    'port': int(request.form['port'].strip()),
                    'user': request.form['user'].strip(),
                    'password': request.form['password'],
                    'database': request.form['database'].strip()
                },
                'table_name': request.form['table_name'].strip()
            }
        elif conn_type == 'api':
            credentials = {
                'api_config': {
                    'url': request.form['api_url'].strip(),
                    'api_key': request.form['api_key']
                }
            }

        # 3. Group the shared column mapping
        column_mapping = {
            'location': request.form['map_ubicacion'].strip(),
            'pallet_id': request.form['map_id_palet'].strip(),
            'item_id': request.form['map_id_articulo'].strip(),
            'description': request.form['map_descripcion_articulo'].strip(),
            'quantity': request.form['map_cantidad'].strip(),
            'expiry_date': request.form['map_fecha_caducidad'].strip(),
            'creation_date': request.form['map_creation_date'].strip(),
            'receipt_number': request.form['map_receipt_number'].strip()
        }
        credentials['column_mapping'] = column_mapping

        # 4. Create new DataSource object
        new_source = DataSource(
            user_id=current_user.id,
            name=name,
            type=conn_type
        )
        
        # 5. Set credentials (encryption happens automatically via setter)
        new_source.credentials = credentials

        db.session.add(new_source)
        db.session.commit()
        
        flash('Connection created successfully!', 'success')
        return redirect(url_for('connections'))
        
    except Exception as e:
        flash(f"An error occurred while creating the connection: {e}", "danger")
        return redirect(url_for('connections'))


@app.route('/connections/<int:source_id>/delete', methods=['POST'])
@login_required
def delete_connection(source_id):
    """Deletes a data source."""
    data_source = DataSource.query.get_or_404(source_id)
    if data_source.user_id != current_user.id:
        flash("You do not have permission to delete this resource.", "danger")
        return redirect(url_for('connections'))
    
    db.session.delete(data_source)
    db.session.commit()
    flash("Connection deleted successfully.", "success")
    return redirect(url_for('connections'))


@app.route('/process_connection/<int:source_id>', methods=['POST'])
@login_required
def process_connection(source_id):
    """
    Processes a data analysis request from a pre-configured data source,
    dispatching to the correct connector based on its type.
    """
    source = DataSource.query.get_or_404(source_id)
    if source.user_id != current_user.id:
        flash("You are not authorized to access this data source.", "danger")
        return redirect(url_for('connections'))

    try:
        credentials = source.credentials
        column_mapping = credentials.get('column_mapping', {})
        
        connector = None
        if source.type == 'mysql':
            db_config = credentials.get('db_config', {})
            table_name = credentials.get('table_name')
            if not all([db_config, table_name, column_mapping]):
                raise ValueError("MySQL source configuration is incomplete.")
            connector = SQLConnector(db_config, table_name, column_mapping)
        
        elif source.type == 'api':
            api_config = credentials.get('api_config', {})
            if not all([api_config.get('url'), column_mapping]):
                 raise ValueError("API source configuration is incomplete.")
            connector = APIConnector(api_config, column_mapping)
        
        else:
            raise NotImplementedError(f"Connector for type '{source.type}' is not implemented.")

        connector.connect()
        inventory_df = connector.get_data()
        connector.disconnect()

        if inventory_df.empty:
            flash("No data could be fetched from the data source.", "warning")
            return redirect(url_for('connections'))
        
        # --- Run Engine ---
        rules_path = os.path.join(_data_folder, 'warehouse_rules.xlsx')
        rules_df = pd.read_excel(rules_path)
        
        args = Namespace(debug=False, floating_time=8, straggler_ratio=0.85, stuck_ratio=0.80, stuck_time=6)
        results = run_engine(inventory_df, rules_df, args)
        
        # --- Store Results ---
        report_name = f"Analysis from {source.name}"
        new_report = AnalysisReport(report_name=report_name, user_id=current_user.id)
        db.session.add(new_report)
        db.session.flush()

        # Save location summary
        location_summary = summarize_anomalies_by_location(results)
        new_report.location_summary = json.dumps(location_summary)

        for r in results:
            new_anomaly = Anomaly(
                description=r['anomaly_type'],
                details=r['details'],
                report_id=new_report.id,
                pallet_id=r.get('pallet_id'),
                location=r.get('location'),
                anomaly_type=r['anomaly_type'],
                priority=r['priority']
            )
            db.session.add(new_anomaly)
            
        db.session.commit()
        
        flash("Analysis complete!", "success")
        return redirect(url_for('view_report', report_id=new_report.id))

    except Exception as e:
        flash(f"An error occurred during processing: {e}", "danger")
        return redirect(url_for('connections'))


# --- File Path Configuration ---
if IS_VERCEL:
    # Vercel-specific path for uploads
    UPLOAD_FOLDER = os.path.join('/tmp', 'wie_uploads')
else:
    # Local path for uploads
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
    If the user is authenticated, this page serves as the "new analysis" page.
    If not, it's the main landing page.
    """
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash("Please log in to start an analysis.", "warning")
            return redirect(url_for('login'))
            
        # Cleanup any previous session data to ensure a fresh start
        session.pop('inventory_filepath', None)
        session.pop('rules_filepath', None)

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


@app.route('/dashboard')
@login_required
def dashboard():
    """
    Displays the main dashboard for authenticated users, showing their past analysis reports.
    """
    reports = AnalysisReport.query.filter_by(user_id=current_user.id).order_by(AnalysisReport.timestamp.desc()).all()
    return render_template('dashboard.html', reports=reports)


@app.route('/mapping', methods=['GET'])
@login_required
def mapping():
    """
    Step 2: Displays the column mapping page.
    """
    if 'user_columns' not in session or 'inventory_filepath' not in session:
        return redirect(url_for('index'))

    user_columns = session['user_columns']
    return render_template('mapping.html', user_columns=user_columns)


def default_json_serializer(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, pd.Timestamp)):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    if pd.isna(obj):
        return None
    try:
        return str(obj)
    except Exception:
        return f"Unserializable type: {type(obj).__name__}"

@app.route('/process', methods=['POST'])
@login_required
def process_mapping():
    """
    Processes the uploaded files and the user-defined column mapping.
    """
    inventory_filepath = session.get('inventory_filepath')
    rules_filepath = session.get('rules_filepath')
    report_name_from_file = session.get('original_filename', 'Uploaded File') # Get original filename

    if not inventory_filepath or not rules_filepath:
        flash('File paths are missing from the session. Please upload again.', 'danger')
        return redirect(url_for('index'))

    try:
        inventory_df = pd.read_excel(inventory_filepath)
        rules_df = pd.read_excel(rules_filepath)

        # Apply user's mapping from the form
        mapping = {
            'location': request.form.get('location'),
            'pallet_id': request.form.get('pallet_id'),
            'item_id': request.form.get('item_id'),
            'description': request.form.get('description'),
            'quantity': request.form.get('quantity'),
            'expiry_date': request.form.get('expiry_date'),
            'creation_date': request.form.get('creation_date'),
            'receipt_number': request.form.get('receipt_number')
        }
        
        # Filter out empty values and rename columns
        column_rename_map = {v: k for k, v in mapping.items() if v}
        inventory_df.rename(columns=column_rename_map, inplace=True)
        
        # --- Run Engine ---
        args = Namespace(debug=False, floating_time=8, straggler_ratio=0.85, stuck_ratio=0.80, stuck_time=6)
        results = run_engine(inventory_df, rules_df, args)
        
        # --- Store Results ---
        report_name = f"Analysis of {report_name_from_file}"
        new_report = AnalysisReport(report_name=report_name, user_id=current_user.id)
        db.session.add(new_report)
        db.session.flush()

        location_summary = summarize_anomalies_by_location(results)
        new_report.location_summary = json.dumps(location_summary)

        for r in results:
            new_anomaly = Anomaly(
                description=r['anomaly_type'],
                details=r['details'],
                report_id=new_report.id,
                pallet_id=r.get('pallet_id'),
                location=r.get('location'),
                anomaly_type=r['anomaly_type'],
                priority=r['priority']
            )
            db.session.add(new_anomaly)
            
        db.session.commit()
        
        flash("Analysis complete!", "success")
        # Clean up session and temporary files
        os.remove(inventory_filepath)
        os.remove(rules_filepath)
        session.pop('inventory_filepath', None)
        session.pop('rules_filepath', None)
        session.pop('original_filename', None)
        session.pop('inventory_columns', None)
        
        return redirect(url_for('view_report', report_id=new_report.id))

    except Exception as e:
        flash(f"An error occurred during processing: {e}", "danger")
        return redirect(url_for('mapping'))


@app.route('/report/<int:report_id>')
@login_required
def view_report(report_id):
    report = AnalysisReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return render_template('error.html', error_message="You don't have permission to view this report."), 403
    
    # The template 'results_v2.html' specifically expects a 'report_id' variable for its JavaScript.
    # We pass both the full report object for displaying info and the ID for the script.
    return render_template('results_v2.html', report=report, report_id=report.id)


@app.route('/api/report/<int:report_id>/summary')
@login_required
def get_report_summary(report_id):
    """
    API endpoint that returns a JSON summary of a report for the dashboard.
    """
    report = AnalysisReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return jsonify(error="Unauthorized"), 403

    total_anomalies = Anomaly.query.filter_by(report_id=report_id).count()
    resolved_anomalies = Anomaly.query.filter_by(report_id=report_id, resolved=True).count()
    
    # Correctly count distinct affected pallets
    affected_pallets = db.session.query(Anomaly.pallet_id).filter_by(report_id=report_id).distinct().count()

    # The location summary is now stored as a JSON string in the report itself
    try:
        locations_summary = json.loads(report.location_summary) if report.location_summary else []
    except json.JSONDecodeError:
        locations_summary = []

    critical_locations_count = len(locations_summary)

    kpis = [
        {"label": "Total Anomalies", "value": total_anomalies},
        {"label": "Critical Locations", "value": critical_locations_count},
        {"label": "Affected Pallets", "value": affected_pallets},
        {"label": "Resolved", "value": f"{resolved_anomalies}/{total_anomalies}"}
    ]

    return jsonify({
        "report_name": report.report_name,
        "kpis": kpis,
        "locations": locations_summary
    })

@app.route('/report/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_report(report_id):
    report = AnalysisReport.query.get_or_404(report_id)
    if report.user_id == current_user.id:
        db.session.delete(report)
        db.session.commit()
        flash('Report deleted successfully.', 'success')
    else:
        flash('You do not have permission to delete this report.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/api/anomaly/<int:anomaly_id>/resolve', methods=['POST'])
@login_required
def resolve_anomaly(anomaly_id):
    anomaly = Anomaly.query.get_or_404(anomaly_id)
    report = AnalysisReport.query.get_or_404(anomaly.report_id)
    if report.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    anomaly.resolved = True
    anomaly.resolved_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True, 'resolved_at': anomaly.resolved_at.isoformat()})

@app.route('/report/<int:report_id>/location_details/<path:location_name>')
@login_required
def get_location_details(report_id, location_name):
    """
    API endpoint to get the full details for anomalies at a specific location.
    Now queries the structured 'location' column directly.
    """
    report = AnalysisReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return jsonify({"error": "Permission denied"}), 403

    # Handle the special case where the frontend might request 'Unknown'
    if location_name == 'Unknown':
        query_location = None
    else:
        query_location = location_name

    anomalies_query = Anomaly.query.filter_by(report_id=report_id, location=query_location).all()

    results = []
    for anom in anomalies_query:
        results.append({
            'id': anom.id,
            'resolved': anom.resolved,
            'pallet_id': anom.pallet_id,
            'location': anom.location or 'Unknown',
            'anomaly_type': anom.anomaly_type,
            'priority': anom.priority,
            'details': anom.details
        })

    return jsonify(results)


@app.route('/report/<int:report_id>/details')
@login_required
def get_report_details(report_id):
    """
    API endpoint to get detailed anomaly data for a report.
    """
    report = AnalysisReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return jsonify(error="Unauthorized"), 403

    anomalies_query = Anomaly.query.filter_by(report_id=report_id)
    
    location = request.args.get('location')
    if location:
        anomalies_query = anomalies_query.filter_by(location=location)

    anomalies = anomalies_query.all()

    # We format the output to match what the frontend expects.
    results = []
    for anom in anomalies:
        results.append({
            'id': anom.id,
            'resolved': anom.resolved,
            'pallet_id': anom.pallet_id,
            'location': anom.location,
            'anomaly_type': anom.anomaly_type,
            'priority': anom.priority,
            'details': anom.details # The description from the engine
        })

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5001)