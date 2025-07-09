import os

def get_base_dir():
    """
    Returns the absolute path to the project's root directory.
    In a Vercel environment, this will be '/var/task/'.
    """
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def get_rules_path():
    """
    Constructs the absolute path to the warehouse_rules.xlsx file.
    """
    return os.path.join(get_base_dir(), 'data', 'warehouse_rules.xlsx')

def get_upload_folder():
    """
    Returns the path to the temporary upload folder for Vercel.
    """
    return '/tmp/wie_uploads'