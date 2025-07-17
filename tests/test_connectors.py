import unittest
import polars as pl
import sys
import os

# Add the 'src' directory to the Python path to import the connector
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from connectors import SQLConnector

# --- Test Configuration ---
# These are the credentials for the Docker container we set up.
# Note: The port is 3307 as we changed it.
TEST_DB_CONFIG = {
    'host': 'localhost',
    'user': 'test_user',
    'password': 'test_password',
    'database': 'test_ware_engine',
    'port': 3307
}

# This simulates the mapping a user would provide.
# Key: The standard column name our engine expects.
# Value: The actual column name in the source database table.
TEST_COLUMN_MAPPING = {
    'location': 'location',
    'pallet_id': 'pallet_id',
    'item_id': 'item_id',
    'description': 'description',
    'quantity': 'quantity',
    'expiry_date': 'expiry_date',
    'creation_date': 'creation_date',
    'receipt_number': 'receipt_number'
}

TEST_TABLE_NAME = 'inventory'


class TestSQLConnector(unittest.TestCase):

    def test_full_connection_flow(self):
        """
        Tests the complete connect -> get_data -> disconnect flow.
        """
        print("\\n--- Running test_full_connection_flow ---")
        
        # 1. Initialization
        connector = SQLConnector(
            db_config=TEST_DB_CONFIG,
            table_name=TEST_TABLE_NAME,
            column_mapping=TEST_COLUMN_MAPPING
        )
        self.assertIsNotNone(connector)

        try:
            # 2. Connection
            connector.connect()
            self.assertIsNotNone(connector.connection, "Connection object should not be None after connect()")

            # 3. Get Data
            df = connector.get_data()
            self.assertIsInstance(df, pl.DataFrame, "get_data() should return a Polars DataFrame")
            self.assertFalse(df.is_empty(), "DataFrame should not be empty")
            
            # 4. Verification
            print("Verifying DataFrame content...")
            self.assertEqual(len(df), 4, "Should fetch 4 rows from the test database")
            
            expected_columns = list(TEST_COLUMN_MAPPING.keys())
            self.assertListEqual(sorted(list(df.columns)), sorted(expected_columns), "DataFrame columns should match the renamed keys from the mapping")
            
            # Check a sample value
            # Let's find the row for 'Canned Corn' and check its quantity
            canned_corn_row = df.filter(pl.col('item_id') == 'SKU12346')
            self.assertEqual(canned_corn_row['quantity'][0], 150, "Quantity for Canned Corn should be 150")

            print("DataFrame content verified successfully.")

        finally:
            # 5. Disconnection
            # This is in a 'finally' block to ensure it runs even if assertions fail
            connector.disconnect()
            print("--- Test finished ---")


if __name__ == '__main__':
    # This allows us to run the test directly from the command line
    unittest.main() 