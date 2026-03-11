#!/usr/bin/env python3
"""VulnGuard – Development server entry point.

Usage:
    python run.py                  # Start development server
    python run.py --port 8000      # Use custom port
    python run.py --no-debug       # Disable debug / auto-reload
"""

import argparse
import os

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

from app import create_app


def main():
    parser = argparse.ArgumentParser(description="VulnGuard Development Server")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind (default: 5000)')
    parser.add_argument('--no-debug', action='store_true', help='Disable debug mode')
    args = parser.parse_args()

    app = create_app()
    print(f"\n🚀  Starting VulnGuard API on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=not args.no_debug)


if __name__ == '__main__':
    main()
