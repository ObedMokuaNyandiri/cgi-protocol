import argparse
import os
import secrets
import shutil
import subprocess
import sys


def print_header(title: str):
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


def create_env_file(auto: bool):
    print_header("Step 1: Environment Setup")
    
    env_file = ".env"
    env_example = ".env.example"
    
    if os.path.exists(env_file):
        if auto:
            print(f"Using existing {env_file}.")
        else:
            ans = input(f"A {env_file} file already exists. Overwrite? (y/N): ")
            if ans.lower() != 'y':
                print(f"Keeping existing {env_file}.")
                return
    
    # Read the example file to use as a template
    if not os.path.exists(env_example):
        print(f"Error: {env_example} not found. Ensure you are running this from the CGI-Protocol root.")
        sys.exit(1)
        
    with open(env_example, "r", encoding="utf-8") as f:
        env_content = f.read()

    # Generate a strong private key passphrase
    passphrase = secrets.token_urlsafe(32)
    
    # Find and replace the passphrase line
    if "PRIVATE_KEY_PASSPHRASE=" in env_content:
        env_content = env_content.replace("PRIVATE_KEY_PASSPHRASE=", f"PRIVATE_KEY_PASSPHRASE={passphrase}")
    else:
        env_content += f"\nPRIVATE_KEY_PASSPHRASE={passphrase}\n"

    # Configure AI Backend
    backend = "gemini_native"
    endpoint = ""
    api_key = ""
    model_id = "gemini-2.5-flash"
    
    if auto:
        print("Auto mode: Using default gemini_native configuration.")
    else:
        print("\nSelect your AI Backend:")
        print("1. Google Gemini (Cloud, Recommended)")
        print("2. OpenAI (Cloud)")
        print("3. Ollama (Self-Hosted Local)")
        print("4. vLLM (Self-Hosted Local)")
        print("5. Custom / Other")
        
        choice = input("Enter your choice (1-5) [1]: ").strip()
        if choice == "2":
            backend = "openai_compatible"
            endpoint = "https://api.openai.com/v1"
            api_key = input("Enter OpenAI API Key (sk-...): ").strip()
            model_id = "gpt-4o-mini"
        elif choice == "3":
            backend = "ollama_local"
            endpoint = "http://localhost:11434"
            model_id = input("Enter Ollama Model ID (e.g. llama3.2): ").strip() or "llama3.2"
        elif choice == "4":
            backend = "vllm_local"
            endpoint = "http://localhost:8000/v1"
            model_id = input("Enter vLLM Model ID: ").strip()
        elif choice == "5":
            backend = input("Enter AI_BACKEND_TYPE: ").strip()
            endpoint = input("Enter AI_ENDPOINT_URL: ").strip()
            api_key = input("Enter AI_API_KEY: ").strip()
            model_id = input("Enter MODEL_ID: ").strip()
        elif choice == "1" or not choice:
            backend = "gemini_native"
            api_key = input("Enter Google Gemini API Key: ").strip()
            model_id = "gemini-2.5-flash"

    if not auto and choice in ["3", "4"]:
        is_docker = input("\nWill you be deploying the CGI-Gateway in Docker? (y/N): ").strip().lower() == "y"
        if is_docker:
            print("  -> Updating endpoint to use host.docker.internal for Docker compatibility.")
            endpoint = endpoint.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")

    # We need to manually append these or replace them since the example file has them commented or blank
    lines = env_content.splitlines()
    new_lines = []
    
    overrides = {
        "AI_BACKEND_TYPE": backend,
        "AI_ENDPOINT_URL": endpoint,
        "AI_API_KEY": api_key,
        "MODEL_ID": model_id,
        "API_KEYS_FILE": "auth/api_keys.json",
        "ANCHOR_ENABLED": "true"
    }

    for line in lines:
        replaced = False
        for k, v in list(overrides.items()):
            if line.startswith(f"{k}="):
                new_lines.append(f"{k}={v}")
                # mark as overridden so we don't append it again
                overrides.pop(k)
                replaced = True
                break
        if not replaced:
            new_lines.append(line)
        
    for k, v in overrides.items():
        if v is not None:
            new_lines.append(f"{k}={v}")

    with open(env_file, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines))
        
    print(f"Successfully configured {env_file}")
    print(f"   Backend: {backend}")
    print(f"   Model: {model_id}")


def create_api_key(auto: bool):
    print_header("Step 2: Provision First API Key")
    
    if auto:
        org_name = "AutoTestOrg"
    else:
        org_name = input("Enter your Organization Name for the first API Key [Admin]: ").strip() or "Admin"
        
    try:
        # Run the existing keygen script
        result = subprocess.run(
            [sys.executable, "auth/keygen.py", "--api-key", org_name],
            capture_output=True,
            text=True,
            check=True
        )
        print("First API Key generated successfully:")
        print(result.stdout)
        
        # Save the raw key to a file for auto testing
        if auto:
            lines = result.stdout.splitlines()
            for line in lines:
                if line.startswith("Raw Key:"):
                    raw_key = line.split(":", 1)[1].strip()
                    with open("auto_test_key.txt", "w") as f:
                        f.write(raw_key)
                    break

    except subprocess.CalledProcessError as e:
        print("Failed to generate API Key.")
        print(e.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="CGI-Protocol Deployment Wizard")
    parser.add_argument("--auto", action="store_true", help="Run in headless mode without prompting")
    args = parser.parse_args()

    print("\nCGI-Protocol Setup Wizard")
    print("This utility will prepare your node for production deployment.")
    
    create_env_file(args.auto)
    create_api_key(args.auto)
    
    print_header("Setup Complete!")
    print("You can now start your API Gateway:")
    print("  python api_gateway.py")
    print("or use Docker:")
    print("  docker-compose up --build -d")
    print("\nFor client applications and agents, provide the raw API key generated above in the 'X-API-Key' header.")


if __name__ == "__main__":
    main()
