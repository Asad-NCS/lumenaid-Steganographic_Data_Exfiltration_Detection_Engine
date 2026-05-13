import subprocess
import sys
import os
import time
import atexit
from dotenv import load_dotenv

load_dotenv()

processes = []

def cleanup():
    print("\n[*] Shutting down all services...")
    for p in processes:
        try:
            p.terminate()
        except:
            pass
    print("[+] All services stopped cleanly. Goodbye!")

def main():
    # Register cleanup function to run on exit
    atexit.register(cleanup)
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("==========================================")
    print("   LUMENAID SYSTEM - PYTHON ORCHESTRATOR")
    print("==========================================\n")
    
    # 1. Start MongoDB
    mongo_data = os.path.join(root_dir, ".mongo-data")
    if not os.path.exists(mongo_data):
        os.makedirs(mongo_data)
        
    print("[1/3] Starting MongoDB (Port 27017)...")
    # We send mongo logs to DEVNULL so it doesn't spam the terminal
    mongo_cmd = ["mongod", "--dbpath", mongo_data, "--port", "27017", "--bind_ip", "127.0.0.1"]
    try:
        mongo_proc = subprocess.Popen(mongo_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(mongo_proc)
    except FileNotFoundError:
        print("[ERROR] 'mongod' not found. Make sure MongoDB is installed and in your Windows PATH.")
        sys.exit(1)
        
    time.sleep(2) # Give Mongo a second to boot
    
    # 2. Start Backend
    print("[2/3] Starting FastAPI Backend (Port 8000)...")
    backend_cmd = [sys.executable, "-m", "uvicorn", "api.main:app", "--port", "8000"]
    backend_proc = subprocess.Popen(backend_cmd, cwd=root_dir)
    processes.append(backend_proc)
    
    time.sleep(2) # Give Backend a second to bind
    
    # 3. Start Frontend
    print("[3/3] Starting React Frontend (Port 3000)...")
    dashboard_dir = os.path.join(root_dir, "dashboard")
    
    # shell=True is required on Windows for 'npm' command to be found properly
    frontend_cmd = ["npm", "start"]
    frontend_proc = subprocess.Popen(frontend_cmd, cwd=dashboard_dir, shell=True)
    processes.append(frontend_proc)
    
    print("\n[+] ALL SERVICES RUNNING IN THIS TERMINAL!")
    print("[+] Press Ctrl+C right here to gracefully stop everything at once.\n")
    print("-" * 50)
    
    try:
        # Keep the main script alive so we can see the logs
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # The atexit cleanup function will automatically handle termination
        pass

if __name__ == "__main__":
    main()
