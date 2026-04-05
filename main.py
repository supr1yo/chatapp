from src.app import setup
from src.gui import launch

if __name__ == "__main__":
    conn, shared_key, other_sign = setup()
    launch(conn, shared_key, other_sign)