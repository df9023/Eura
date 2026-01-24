# Setup Guide for New Computer

This guide lists all the technical software and tools you need to download and install to work on the Eura project.

## Required Software Downloads

### 1. **Python 3.11**
   - **Download from**: https://www.python.org/downloads/
   - **Version**: Python 3.11 (as specified in `runtime.txt`)
   - **Important**: During installation, check "Add Python to PATH"
   - **Verify**: After installation, open terminal and run:
     ```bash
     python --version
     ```
     Should show: `Python 3.11.x`

### 2. **Git**
   - **Download from**: https://git-scm.com/download/win
   - **Why needed**: Version control for the repository
   - **Verify**: After installation, run:
     ```bash
     git --version
     ```

### 3. **Code Editor/IDE** (Choose one)
   - **Cursor** (Recommended - you're already using this!)
   - **VS Code**: https://code.visualstudio.com/
   - **PyCharm**: https://www.jetbrains.com/pycharm/

## Python Package Installation

After installing Python, install all project dependencies:

```bash
# Navigate to project directory
# Replace with your actual project path (e.g., C:\Users\danie\Documents\GitHub\Eura)
cd <your-project-path>

# Create a virtual environment (recommended)
# IMPORTANT: Use Python 3.11 specifically (not 3.14) to avoid Rust compilation issues
# On Windows, if you have multiple Python versions:
py -3.11 -m venv venv
# Or if python points to 3.11:
python -m venv venv

# Activate virtual environment
# On Windows PowerShell (if you get execution policy error, run this first):
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1
# On Windows CMD:
venv\Scripts\activate.bat

# Upgrade pip first (important for Python 3.14)
python -m pip install --upgrade pip setuptools wheel

# Install all dependencies
python -m pip install -r requirements.txt
```

**Note**: If you encounter Rust/Cargo errors with `pydantic_core`:

**First, ensure Rust/Cargo is on PATH:**
1. **Restart your terminal** after installing Rust (so PATH updates)
2. Or manually add to PATH in current session:
   ```powershell
   $env:Path += ";C:\Users\$env:USERNAME\.cargo\bin"
   ```

**Then try installing:**
1. **Install pydantic packages first** (they have pre-built wheels):
   ```powershell
   python -m pip install pydantic==2.5.0 pydantic-core==2.14.1
   ```
2. **Then install the rest**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

**If Python 3.14 doesn't have wheels available:**
- Consider using Python 3.11 (as specified in `runtime.txt`) which has better package support
- Or install Rust properly from https://rustup.rs/ and ensure it's on PATH

## Required API Keys & Credentials

You'll need to create a `.env` file in the project root with the following:

### 1. **GitHub App Credentials** (Required)
   - **GITHUB_APP_ID**: Your GitHub App ID
   - **GITHUB_PRIVATE_KEY**: Your GitHub App private key (PEM format)
   - **GITHUB_TOKEN**: (Optional) Personal Access Token for public repo scanning with higher rate limits
   - **How to get**: 
     - Create a GitHub App at: https://github.com/settings/apps/new
     - Or use existing GitHub App credentials

### 2. **OpenAI API Key** (Required)
   - **OPENAI_API_KEY**: Your OpenAI API key
   - **How to get**: https://platform.openai.com/api-keys
   - **Why needed**: For LLM-based code analysis

### 3. **Supabase Credentials** (Optional - for database persistence)
   - **SUPABASE_URL**: Your Supabase project URL
   - **SUPABASE_SERVICE_ROLE_KEY**: Your Supabase service role key
   - **How to get**: https://supabase.com/dashboard
   - **Note**: Project works without this for ephemeral scans

### 4. **Environment Variables Template**

Create a `.env` file in the project root:

```env
# GitHub App Authentication (required for private repos)
GITHUB_APP_ID=your-app-id-here
GITHUB_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
your-private-key-content-here
-----END RSA PRIVATE KEY-----

# GitHub Personal Access Token (optional, for public repo scanning)
GITHUB_TOKEN=your-personal-access-token-here

# OpenAI API
OPENAI_API_KEY=sk-your-openai-key-here

# Supabase (optional for local dev)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here

# CORS (optional, defaults to *)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Limits (optional, defaults shown)
MAX_FILES=120
MAX_FILE_BYTES=120000
MAX_CHARS_PER_FILE=12000
```

## Optional Software (For Frontend Development)

### Node.js (Only if working on frontend)
   - **Download from**: https://nodejs.org/
   - **Version**: LTS version recommended
   - **Note**: Backend is Python-only, Node.js only needed if developing the Lovable React frontend separately

## Verify Installation

After setting everything up, verify your installation:

```bash
# Check Python version
python --version
# Should show: Python 3.11.x

# Check pip
pip --version

# Check if dependencies installed correctly
pip list | findstr fastapi
# Should show: fastapi

# Test running the server
uvicorn app.main:app --reload --port 8000
# Server should start at http://localhost:8000
# API docs at http://localhost:8000/docs
```

## Quick Start Commands

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies (if not done already)
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --reload --port 8000

# Run tests
pytest tests/ -v

# Run Phase 0 contract tests
pytest tests/test_phase0_contract.py -v
```

## Troubleshooting

### Python not found
- Make sure Python is added to PATH during installation
- Restart terminal after installing Python

### pip install fails
- Make sure you're using Python 3.11
- Try upgrading pip: `python -m pip install --upgrade pip`

### Environment variables not loading
- Make sure `.env` file is in the project root (same directory as `requirements.txt`)
- Check that variable names match exactly (case-sensitive)

### GitHub App authentication fails
- Verify GITHUB_APP_ID is correct
- Check that GITHUB_PRIVATE_KEY includes the full PEM format with headers
- Ensure GitHub App has necessary permissions

## Summary Checklist

- [ ] Python 3.11 installed
- [ ] Git installed
- [ ] Virtual environment created and activated
- [ ] All Python packages installed (`pip install -r requirements.txt`)
- [ ] `.env` file created with required credentials:
  - [ ] GITHUB_APP_ID
  - [ ] GITHUB_PRIVATE_KEY
  - [ ] OPENAI_API_KEY
  - [ ] (Optional) SUPABASE_URL
  - [ ] (Optional) SUPABASE_SERVICE_ROLE_KEY
- [ ] Server runs successfully (`uvicorn app.main:app --reload`)
- [ ] Tests pass (`pytest tests/ -v`)

## Additional Resources

- **Project Documentation**: See `docs/WORKFLOW_AND_ARCHITECTURE.md` for detailed architecture
- **API Documentation**: Once server is running, visit http://localhost:8000/docs
- **Python Virtual Environments**: https://docs.python.org/3/tutorial/venv.html
