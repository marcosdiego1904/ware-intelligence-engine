from abc import ABC, abstractmethod
import polars as pl
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
import requests

class DataConnector(ABC):
    @abstractmethod
    def connect(self):
        """Establishes the connection to the data source."""
        pass

    @abstractmethod
    def get_data(self) -> pl.DataFrame:
        """
        Fetches data from the source and returns it as a Polars DataFrame.
        This method MUST always return a Polars DataFrame structured according
        to the application's expected format.
        """
        pass

    @abstractmethod
    def disconnect(self):
        """Closes the connection to the data source."""
        pass

class SQLConnector(DataConnector):
    def __init__(self, db_config, table_name, column_mapping):
        self.db_config = db_config
        self.table_name = table_name
        self.column_mapping = column_mapping
        self.engine = None
        self.connection = None

    def connect(self):
        try:
            # Construct the connection string from the config dictionary, now including the port.
            host = self.db_config['host']
            port = self.db_config.get('port')
            host_str = f"{host}:{port}" if port else host

            connection_string = (
                f"mysql+mysqlconnector://{self.db_config['user']}:{self.db_config['password']}"
                f"@{host_str}/{self.db_config['database']}"
            )
            self.engine = create_engine(connection_string)
            self.connection = self.engine.connect()
            print("Database connection successful.")
        except SQLAlchemyError as e:
            print(f"Error connecting to the database: {e}")
            raise

    def get_data(self) -> pl.DataFrame:
        if not self.connection:
            print("Connection not established. Call connect() first.")
            return pl.DataFrame()

        try:
            # The mapping is {'engine_column': 'database_column'}.
            # We create SQL aliases: SELECT `database_column` AS `engine_column`
            query_columns = [f"`{db_col}` AS `{engine_col}`" for engine_col, db_col in self.column_mapping.items()]
            
            # Ensure required columns that might not be mapped are still selected, assuming they exist with the engine name.
            # This is a fallback and good mapping is preferred.
            engine_columns_in_map = set(self.column_mapping.keys())
            required_engine_columns = {'location', 'pallet_id', 'item_id', 'description', 'quantity', 'expiry_date', 'creation_date', 'receipt_number'}
            
            for col in required_engine_columns:
                if col not in engine_columns_in_map:
                    query_columns.append(f"`{col}`") # Assume it exists with the engine name if not mapped

            query = f"SELECT {', '.join(query_columns)} FROM `{self.table_name}`"
            
            df = pl.read_database(query=text(query), connection=self.connection)

            print(f"Successfully fetched {len(df)} rows from table '{self.table_name}'.")
            return df
            
        except SQLAlchemyError as e:
            print(f"Error executing query: {e}")
            return pl.DataFrame() # Return empty DataFrame on error
        except Exception as e:
            print(f"An unexpected error occurred during data fetching: {e}")
            return pl.DataFrame()

    def disconnect(self):
        if self.connection:
            self.connection.close()
            if self.engine:
                self.engine.dispose()
            print("Database connection closed.")


class APIConnector(DataConnector):
    def __init__(self, api_config, column_mapping):
        self.base_url = api_config.get('url')
        self.api_key = api_config.get('api_key')
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        if self.api_key:
            # Common practice is to send the API key in an 'Authorization' header.
            # This might need to be adjusted depending on the specific API's requirements.
            self.headers['Authorization'] = f'Bearer {self.api_key}'

        self.column_mapping = column_mapping
        self.session = None

    def connect(self):
        """Initializes a requests.Session for making HTTP requests."""
        try:
            self.session = requests.Session()
            self.session.headers.update(self.headers)
            print(f"API Connector session initialized for URL: {self.base_url}")
        except Exception as e:
            print(f"Error initializing requests session: {e}")
            raise

    def get_data(self) -> pl.DataFrame:
        """Fetches data from the API endpoint and normalizes it into a DataFrame."""
        if not self.session:
            print("Session not established. Call connect() first.")
            return pl.DataFrame()

        try:
            response = self.session.get(self.base_url)
            response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
            
            data = response.json()
            
            df = pl.from_dicts(data)
            
            # Rename columns based on the user's mapping.
            # The mapping is {'engine_column': 'api_column'}. We need to reverse it for renaming.
            rename_map = {api_col: engine_col for engine_col, api_col in self.column_mapping.items()}
            df = df.rename(rename_map)

            # --- Type Conversion ---
            # Ensure date columns are converted to datetime objects, crucial for calculations.
            date_columns = ['creation_date', 'expiry_date']
            for col in date_columns:
                if col in df.columns:
                    # 'errors="coerce"' will turn any unparseable date into NaT (Not a Time)
                    df = df.with_columns(pl.col(col).str.to_datetime(strict=False))

            print(f"Successfully fetched and normalized {len(df)} records from the API.")
            return df

        except requests.exceptions.RequestException as e:
            print(f"Error fetching data from API: {e}")
            return pl.DataFrame()
        except (ValueError, TypeError) as e:
            # Handles JSON decoding errors or issues with json_normalize
            print(f"Error processing JSON response: {e}")
            return pl.DataFrame()

    def disconnect(self):
        """Closes the requests.Session."""
        if self.session:
            self.session.close()
            print("API Connector session closed.") 