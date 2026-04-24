import pyodbc

def get_connection():
    """
    Establishes a connection to the SQL Server 'iam_security' database.
    Windows only — uses ODBC Driver 18 for SQL Server with Windows Authentication.
    """
    import os
    server = os.getenv('DB_SERVER', r'.\SQLEXPRESS')
    database = os.getenv('DB_NAME', 'iam_security')

    conn_str = (
        f'DRIVER={{ODBC Driver 18 for SQL Server}};'
        f'SERVER={server};'
        f'DATABASE={database};'
        f'Trusted_Connection=yes;'
        f'TrustServerCertificate=yes;'
    )
    
    try:
        conn = pyodbc.connect(conn_str)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def test_connection():
    """
    Tests the database connection and prints the result.
    """
    conn = get_connection()
    if conn:
        print("Success: Database connection established!")
        conn.close()
    else:
        print("Error: Could not connect to the database.")

if __name__ == "__main__":
    test_connection()
