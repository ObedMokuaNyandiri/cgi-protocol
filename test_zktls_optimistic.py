import subprocess
import time
import sys

def print_header(title: str):
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60 + "\n")

def run_mode(mode: str):
    print(f"[+] Starting CGI Local Wrapper in {mode.upper()} Mode...\n")
    start = time.time()
    
    try:
        # Run cgi_runtime.py in the specified mode
        result = subprocess.run(
            [sys.executable, "cgi_runtime.py", f"--mode={mode}"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running in {mode} mode!")
        print(e.stderr)
        sys.exit(1)
        
    duration = time.time() - start
    print(f"[+] {mode.upper()} Execution Completed in {duration:.2f} seconds.")

if __name__ == "__main__":
    print_header("CGI PROTOCOL: LOCAL SIDECAR ARCHITECTURE (0.0001% PIVOT)")
    
    # Generate the initial epoch token (assuming auth/generate_token.py exists and works)
    print("[+] Generating Authentication Token for User...\n")
    subprocess.run([sys.executable, "auth/generate_token.py"], check=True)
    
    # 1. zkTLS API Mode
    print_header("SCENARIO 1: WRAPPING A CLOUD LLM API (zkTLS)")
    print("In this scenario, the user queries an external LLM (e.g., Gemini) via API key.")
    print("The CGI Wrapper intercepts the call, establishing a zkTLS session to prove provenance.")
    run_mode("api")
    
    # 2. Local Optimistic Mode
    print_header("SCENARIO 2: WRAPPING A LOCAL MODEL (OPTIMISTIC COMMITS)")
    print("In this scenario, the user queries a local LLM running on their own GPU.")
    print("The CGI Wrapper intercepts the output and generates a fast Merkle root of the execution trace.")
    
    print("[+] Generating Authentication Token for Scenario 2...\n")
    subprocess.run([sys.executable, "auth/generate_token.py"], check=True)
    
    run_mode("local")
    
    print_header("DEMO COMPLETE")
    print("The CGI Protocol has successfully transitioned to a Zero-Cost, Local Cryptographic Sidecar!")
