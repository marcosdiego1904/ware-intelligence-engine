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

# Add the 'src' directory to the Python path to resolve local imports in Vercel.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# We assume your engine is in 'main.py' inside the same 'src' folder
from main import run_engine, summarize_anomalies_by_location

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

class AnalysisReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_name = db.Column(db.String(120), nullable=False, default=f"Analysis Report")
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    anomalies = db.relationship('Anomaly', backref='report', lazy=True, cascade="all, delete-orphan")
    location_summary = db.Column(db.Text, nullable=True) # Stores a JSON string of the location summary

class Anomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True) # Could store JSON or other details
    report_id = db.Column(db.Integer, db.ForeignKey('analysis_report.id'), nullable=False)
    resolved = db.Column(db.Boolean, default=False, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)

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
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj).__name__} not serializable")

@app.route('/process', methods=['POST'])
@login_required
def process_mapping():
    """
    Step 3: Processes the mapping, runs the engine, and displays the results.
    """
    try:
        report_count = AnalysisReport.query.filter_by(user_id=current_user.id).count()
        if report_count >= 3 and current_user.username != 'marcosbarzola@devbymarcos.com':
            return render_template('error.html', error_message="You have reached the maximum limit of 3 analysis reports."), 403

        inventory_path = session.get('inventory_filepath')
        rules_path = session.get('rules_filepath')

        if not all([inventory_path, rules_path]):
            return render_template('error.html', error_message="Session expired. Please start over."), 400

        column_mapping = {request.form[key]: key for key in request.form}
        
        inventory_df = pd.read_excel(inventory_path)
        inventory_df.rename(columns=column_mapping, inplace=True)
        
        if 'creation_date' in inventory_df.columns:
            inventory_df['creation_date'] = pd.to_datetime(inventory_df['creation_date'])
        
        rules_df = pd.read_excel(rules_path)
        
        args = Namespace(debug=False, floating_time=8, straggler_ratio=0.85, stuck_ratio=0.80, stuck_time=6)
        
        anomalies = run_engine(inventory_df, rules_df, args)
        
        # ✅ AQUÍ GENERAMOS Y GUARDAMOS EL RESUMEN
        location_summary = summarize_anomalies_by_location(anomalies)
        report_name = f"Analysis - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
        
        new_report = AnalysisReport()
        new_report.report_name=report_name
        new_report.user_id=current_user.id
        new_report.location_summary=json.dumps(location_summary) # Guardamos como texto JSON
        
        db.session.add(new_report)
        db.session.flush()

        for item in anomalies:
            anomaly = Anomaly()
            if isinstance(item, dict):
                anomaly.description = item.get('anomaly_type', 'Uncategorized Anomaly')
                anomaly.details = json.dumps(item, default=default_json_serializer)
            else:
                anomaly.description = str(item)
                anomaly.details = None
            anomaly.report_id = new_report.id
            db.session.add(anomaly)
            
        db.session.commit()

        return redirect(url_for('view_report', report_id=new_report.id))

    except Exception as e:
        print(f"[ERROR] during processing: {e}")
        error_msg = f"An error occurred while analyzing the data. (Detail: {type(e).__name__})"
        return render_template('error.html', error_message=error_msg), 500
    
    finally:
        for key in ['inventory_filepath', 'rules_filepath', 'user_columns']:
            item = session.pop(key, None)
            if isinstance(item, str) and item.startswith(UPLOAD_FOLDER) and os.path.exists(item):
                try:
                    os.remove(item)
                except OSError:
                    pass

@app.route('/report/<int:report_id>')
@login_required
def view_report(report_id):
    """
    Displays a specific past analysis report from the database.
    """
    report = AnalysisReport.query.get_or_404(report_id)

    # Security check
    if report.user_id != current_user.id:
        flash("You do not have permission to view this report.", "danger")
        return redirect(url_for('dashboard'))

    # Renderiza el nuevo template, pasando solo el ID del reporte
    return render_template('results_v2.html', report_id=report.id)


@app.route('/report/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_report(report_id):
    """
    Deletes a specific analysis report from the database.
    """
    report = AnalysisReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        flash("You are not authorized to delete this report.", "danger")
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(report)
        db.session.commit()
        flash("Your report has been deleted.", "success")
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] deleting report: {e}")
        flash("An error occurred while deleting the report.", "danger")
    
    return redirect(url_for('dashboard'))


@app.route('/api/anomaly/<int:anomaly_id>/resolve', methods=['POST'])
@login_required
def resolve_anomaly(anomaly_id):
    anomaly = Anomaly.query.get_or_404(anomaly_id)
    
    # Verify that the anomaly belongs to a report owned by the current user
    if anomaly.report.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    anomaly.resolved = True
    anomaly.resolved_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Anomaly resolved successfully.'})


@app.route('/report/<int:report_id>/location_details/<path:location_name>')
@login_required
def get_location_details(report_id, location_name):
    """
    API endpoint para obtener detalles de una ubicación específica de un reporte.
    """
    # 1. Buscar el reporte y verificar permisos
    report = AnalysisReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return {"error": "Unauthorized"}, 403

    # Si el nombre de la ubicación es 'N/A', necesitamos manejarlo de forma especial
    # ya que la URL no puede contener el carácter '/' directamente.
    # Por ahora, asumimos que no hay problemas de codificación.

    # 2. Filtrar las anomalías para la ubicación específica
    location_anomalies = []
    for anomaly in report.anomalies:
        if not anomaly.details:
            continue

        details = json.loads(anomaly.details)
        # Comparamos ignorando mayúsculas/minúsculas y espacios
        if details.get('location', '').strip().upper() == location_name.strip().upper():
            location_anomalies.append(details)

    if not location_anomalies:
        return {"error": "No anomalies found for this location"}, 404

    # 3. Procesar los datos para el frontend
    pallet_list = sorted(list(set([d.get('pallet_id', 'N/A') for d in location_anomalies])))

    anomaly_types = [d.get('anomaly_type', 'Unknown') for d in location_anomalies]
    anomaly_counts = pd.Series(anomaly_types).value_counts()

    chart_data = {
        'labels': anomaly_counts.index.tolist(),
        'data': anomaly_counts.values.tolist()
    }

    # 4. Devolver los datos como JSON
    return {
        "location": location_name,
        "pallets": pallet_list,
        "chart": chart_data
    }
@app.route('/report/<int:report_id>/details')
@login_required
def get_report_details(report_id):
    report = AnalysisReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    # Procesar anomalías
    processed_anomalies = []
    for anomaly in report.anomalies:
        try:
            details_data = json.loads(anomaly.details) if anomaly.details else {}
            # Important: Add the database ID and resolved status to the payload
            details_data['id'] = anomaly.id
            details_data['resolved'] = anomaly.resolved
            details_data['resolved_at'] = anomaly.resolved_at.isoformat() if anomaly.resolved_at else None
            processed_anomalies.append(details_data)
        except json.JSONDecodeError:
            continue

    # Agrupar anomalías por ubicación
    locations_map = {}
    for anomaly in processed_anomalies:
        location = anomaly.get('location', 'N/A')
        if location not in locations_map:
            locations_map[location] = []
        locations_map[location].append(anomaly)

    # Formatear resumen de ubicaciones
    location_summary = sorted(
        [{"name": name, "anomaly_count": len(anoms), "anomalies": anoms} for name, anoms in locations_map.items()],
        key=lambda x: x['anomaly_count'],
        reverse=True
    )

    # Calcular KPIs
    high_priority_list = ['VERY HIGH', 'HIGH']
    kpis = [
        {'label': 'Total Anomalies', 'value': len(processed_anomalies)},
        {'label': 'Priority Alerts', 'value': sum(1 for a in processed_anomalies if a.get('priority') in high_priority_list)},
        {'label': 'Affected Locations', 'value': len(location_summary)},
        {'label': 'Main Issue', 'value': max(set(a['anomaly_type'] for a in processed_anomalies), key=lambda t: [a['anomaly_type'] for a in processed_anomalies].count(t)) if processed_anomalies else 'N/A'},
        {'label': 'Avg. Resolution Time', 'value': 'N/A'} # KPI simulado
    ]

    return jsonify({
        "reportId": report.id,
        "reportName": report.report_name,
        "kpis": kpis,
        "locations": location_summary
    })

# --- Entry Point to Run the Application ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)