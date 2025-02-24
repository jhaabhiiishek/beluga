### Backend Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/jhaabhiiishek/beluga.git
   cd malware-detection-tool/backend
   ```

2. **Create and activate a Python virtual environment:**

   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix or MacOS:
   source venv/bin/activate
   ```

3. **Install backend dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

   Ensure your `requirements.txt` includes packages such as:
   - Flask
   - flask-cors
   - flask-sqlalchemy
   - flask-jwt-extended
   - yara-python
   - requests
   - python-dotenv
   - Werkzeug

4. **Set Environment Variables:**

   Create a `.env` file (or set environment variables in your deployment environment) with:
   ```ini
   SECRET_KEY=your_secret_key_here
   JWT_SECRET_KEY=your_jwt_secret_here
   API_KEY=your_default_virustotal_api_key_here
   ```
   
5. **Initialize the Database:**

   If using SQLite, delete any existing `scan_logs.db` file (for development) and let the application create a new one:
   ```bash
   del scan_logs.db   # on Windows
   rm scan_logs.db    # on Unix/MacOS
   python app.py      # This will create a new database with updated models.
   ```

6. **Run the Backend:**

   ```bash
   python app.py
   ```

   The backend will start on [http://localhost:5000](http://localhost:5000).

And then follow the steps in the https://github.com/jhaabhiiishek/beluga-frontend.git