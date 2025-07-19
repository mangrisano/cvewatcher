#!/usr/bin/env python
"""Development server launcher script."""

import subprocess
import sys


def main():
    """Run the FastAPI development server."""
    cmd = ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\nServer stopped.")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        print(f"Error starting server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
