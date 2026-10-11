"""Start the local dashboard; choose a capture adapter in the UI."""
import argparse
from app.dashboard.dashboard import app, initialize_database

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisNet dashboard")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    initialize_database()
    print(f"\nAegisNet: http://127.0.0.1:{args.port}\n")
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False, threaded=True)
