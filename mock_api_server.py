from flask import Flask, jsonify, abort
import os
import json

# --- Configuration ---
# Creates a new Flask application
app = Flask(__name__)
# Defines the path to our mock data file
DATA_FILE = os.path.join('data', 'mock_api_data.json')

# --- API Endpoint ---
@app.route('/inventory', methods=['GET'])
def get_inventory():
    """
    This endpoint reads the mock JSON data from the file and returns it.
    It simulates a real inventory API.
    """
    try:
        # Opens and reads the data file
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        # Returns the data as a JSON response
        return jsonify(data)
    except FileNotFoundError:
        # If the file doesn't exist, return a 404 Not Found error
        abort(404, description="Data file not found.")
    except json.JSONDecodeError:
        # If the file is not valid JSON, return a 500 Internal Server Error
        abort(500, description="Could not decode data file.")

# --- Main Execution ---
if __name__ == '__main__':
    """
    This makes the script runnable. It will start the Flask development server.
    We'll run it on port 5002 to avoid conflicts with the main application (usually on 5000 or 5001).
    """
    print("Starting mock API server on http://127.0.0.1:5002")
    print("Access the mock data at: http://127.0.0.1:5002/inventory")
    print("Press CTRL+C to stop the server.")
    # The 'host' parameter makes it accessible from the local network
    app.run(host='0.0.0.0', port=5002, debug=True) 