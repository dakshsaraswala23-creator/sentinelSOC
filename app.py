"""
SentinelSOC — Mini Security Operations Center
Entry point: run with  python app.py
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    import config
    app.run(debug=config.DEBUG, host="127.0.0.1", port=5000)
