# AWS Single Sign On (SSO) Credential Update
# Allows a user to setup/renew AWS user credentials


import boto3
import webbrowser
import time
import json
from pathlib import Path
from configparser import ConfigParser
import sys
import os
import hashlib
import argparse

# Define the secure file mode (read/write for owner only)
SECURE_FILE_MODE = 0o600

def prompt_input(prompt_text: str) -> str:
    """Print prompt to stderr and get input from stdin to work with eval $()."""
    print(prompt_text, file=sys.stderr, end="")
    sys.stderr.flush()
    return input()


def get_sso_token(start_url: str, sso_region: str):
    """Handles the device authorization flow to get an SSO access token."""
    # Temporarily clear AWS_PROFILE to avoid ProfileNotFound errors during client creation
    original_profile = os.environ.pop('AWS_PROFILE', None)

    try:
        cache_dir = Path.home() / ".aws" / "sso" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        # Generate cache key using SHA1 hash like AWS SDK does
        cache_key = hashlib.sha1(start_url.encode('utf-8')).hexdigest() + ".json"
        cache_file = cache_dir / cache_key
        if cache_file.exists():
            with open(cache_file, "r") as f: data = json.load(f)
            if "accessToken" in data and "expiresAt" in data:
                expires_at = time.strptime(data["expiresAt"], "%Y-%m-%dT%H:%M:%SZ")
                if time.mktime(expires_at) > time.time():
                    print("Using cached SSO access token.", file=sys.stderr)
                    return data["accessToken"]
        print("No valid cached token found. Starting device authorization flow...", file=sys.stderr)
        oidc_client = boto3.client("sso-oidc", region_name=sso_region)
        client_creds = oidc_client.register_client(clientName="my-boto3-sso-app", clientType="public")
        device_authorization = oidc_client.start_device_authorization(
            clientId=client_creds["clientId"], clientSecret=client_creds["clientSecret"], startUrl=start_url
        )
        webbrowser.open(device_authorization["verificationUriComplete"])
        print(f"\nACTION REQUIRED: Your user code is: {device_authorization['userCode']}", file=sys.stderr)
        print(f'please open "{device_authorization["verificationUriComplete"]}" in a web browser if not automatically prompted', file=sys.stderr)
        prompt_input("Press Enter after you have authenticated in the browser...")
        print("Polling for access token...", file=sys.stderr)
        while True:
            try:
                token_response = oidc_client.create_token(
                    clientId=client_creds["clientId"], clientSecret=client_creds["clientSecret"],
                    grantType="urn:ietf:params:oauth:grant-type:device_code", deviceCode=device_authorization["deviceCode"]
                )
                access_token, expires_in = token_response["accessToken"], token_response["expiresIn"]
                expires_at_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + expires_in))

                # Create complete cache file format expected by AWS SDK
                cache_data = {
                    "startUrl": start_url,
                    "region": sso_region,
                    "accessToken": access_token,
                    "expiresAt": expires_at_iso,
                    "clientId": client_creds["clientId"],
                    "clientSecret": client_creds["clientSecret"],
                    "registrationExpiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + client_creds.get("clientSecretExpiresAt", 86400))),
                    "refreshToken": token_response.get("refreshToken", "")
                }

                with open(os.open(cache_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECURE_FILE_MODE), "w") as f:
                    json.dump(cache_data, f, indent=2)

                print("Successfully obtained and cached SSO access token.", file=sys.stderr)
                return access_token
            except oidc_client.exceptions.AuthorizationPendingException:
                time.sleep(device_authorization.get("interval", 5))
            except Exception as e:
                print(f"Error getting token: {e}", file=sys.stderr)
                return None
    finally:
        # Restore original AWS_PROFILE if it was set
        if original_profile is not None:
            os.environ['AWS_PROFILE'] = original_profile

def configure_profile(start_url: str, sso_region: str, access_token: str):
    """Uses SSO access token to configure an AWS profile with secure file permissions."""
    # Temporarily clear AWS_PROFILE to avoid ProfileNotFound errors
    original_profile = os.environ.pop('AWS_PROFILE', None)

    try:
        sso_client = boto3.client("sso", region_name=sso_region)
        accounts = sso_client.list_accounts(accessToken=access_token)["accountList"]
        if not accounts: print("No AWS accounts found.", file=sys.stderr); return None
        for i, acc in enumerate(accounts): print(f"  [{i}] ID: {acc['accountId']}, Name: {acc['accountName']}", file=sys.stderr)
        try:
            account_idx = int(prompt_input("Select an account: "))
            if account_idx < 0 or account_idx >= len(accounts):
                print("Invalid selection. Please enter a valid account number.", file=sys.stderr)
                return None
        except ValueError:
            print("Invalid selection. Please enter a number.", file=sys.stderr)
            return None
        selected_account = accounts[account_idx]

        roles = sso_client.list_account_roles(accessToken=access_token, accountId=selected_account["accountId"])["roleList"]
        if not roles: print(f"No roles found.", file=sys.stderr); return None
        for i, role in enumerate(roles): print(f"  [{i}] Role: {role['roleName']}", file=sys.stderr)
        try:
            role_idx = int(prompt_input("Select a role: "))
            if role_idx < 0 or role_idx >= len(roles):
                print("Invalid selection. Please enter a valid role number.", file=sys.stderr)
                return None
        except ValueError:
            print("Invalid selection. Please enter a number.", file=sys.stderr)
            return None
        selected_role = roles[role_idx]

        profile_name = prompt_input(f"\nEnter a profile name: ")

        config_path = Path.home() / ".aws" / "config"
        config_path.parent.mkdir(exist_ok=True)
        config = ConfigParser()
        if config_path.exists(): config.read(config_path)

        section_name = f"profile {profile_name}"
        config[section_name] = {
            "sso_start_url": start_url,
            "sso_region": sso_region,
            "sso_account_id": selected_account["accountId"],
            "sso_role_name": selected_role["roleName"],
            "region": sso_region,
            "output": "json"
        }

        # Write the config file content to a secured file handler
        with open(os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECURE_FILE_MODE), "w") as f:
            config.write(f)

        print(f"\n✅ Success! Profile '{profile_name}' configured in {config_path}", file=sys.stderr)
        return profile_name
    except Exception as e:
        print(f"An error occurred during profile configuration: {e}", file=sys.stderr)
        return None
    finally:
        # Restore original AWS_PROFILE if it was set
        if original_profile is not None:
            os.environ['AWS_PROFILE'] = original_profile

# --- Phase 3: SSO Login with Secure File Permissions ---

def sso_login(profile_name: str) -> bool:
    """Emulates `aws sso login` and saves credentials with secure file permissions."""
    print(f"\n--- Logging in to profile '{profile_name}' ---", file=sys.stderr)
    config_path = Path.home() / ".aws" / "config"
    if not config_path.exists():
        print(f"Error: AWS config file not found at {config_path}", file=sys.stderr)
        return False

    config = ConfigParser()
    config.read(config_path)
    section_name = f"profile {profile_name}"
    if not config.has_section(section_name):
        print(f"Error: Profile '{profile_name}' not found in {config_path}", file=sys.stderr)
        return False

    sso_config = config[section_name]
    access_token = get_sso_token(sso_config["sso_start_url"], sso_config["sso_region"])
    if not access_token:
        print("Could not get SSO access token. Aborting login.", file=sys.stderr)
        return False

    # Temporarily clear AWS_PROFILE to avoid ProfileNotFound errors
    original_profile = os.environ.pop('AWS_PROFILE', None)

    try:
        sso_client = boto3.client("sso", region_name=sso_config["sso_region"])
        print("Fetching temporary AWS credentials...", file=sys.stderr)
        try:
            response = sso_client.get_role_credentials(
                roleName=sso_config["sso_role_name"], accountId=sso_config["sso_account_id"], accessToken=access_token
            )
            creds = response["roleCredentials"]
        except Exception as e:
            print(f"Error fetching role credentials: {e}", file=sys.stderr)
            return False

        creds_path = Path.home() / ".aws" / "credentials"
        creds_path.parent.mkdir(exist_ok=True)
        creds_config = ConfigParser()
        if creds_path.exists(): creds_config.read(creds_path)

        creds_config[profile_name] = {
            "aws_access_key_id": creds["accessKeyId"],
            "aws_secret_access_key": creds["secretAccessKey"],
            "aws_session_token": creds["sessionToken"],
        }

        # Write the file content
        with open(os.open(creds_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECURE_FILE_MODE), "w") as f:
            creds_config.write(f)

        print(f"✅ Success! Temporary credentials saved to {creds_path}", file=sys.stderr)
        expiration = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(creds['expiration'] / 1000.0))
        print(f"Credentials will expire at: {expiration}", file=sys.stderr)
        return True
    finally:
        # Restore original AWS_PROFILE if it was set
        if original_profile is not None:
            os.environ['AWS_PROFILE'] = original_profile

def main():
    parser = argparse.ArgumentParser(description="AWS SSO Emulation Script (Secure Version)")
    parser.add_argument("--start-url", default="https://yourorghere.awsapps.com/start",
                       help="AWS SSO start URL (default: %(default)s)")
    parser.add_argument("--region", default="us-east-1",
                       help="AWS SSO region (default: %(default)s)")
    parser.add_argument("--profile",
                       help="Profile name (for action 2, defaults to AWS_PROFILE env var)")
    parser.add_argument("--no-env",action='store_true',
                       help="Suppress setting the AWS_PROFILE env var")
    parser.add_argument("--renew",action='store_true',
                       help="Automatically select login with existing profile to renew credentials")

    args = parser.parse_args()

    print("--- AWS SSO Emulation Script ---", file=sys.stderr)
    if args.renew:
        action = "2"
        print("Attempting to renew existing account credentials", file=sys.stderr)
    else:
        action = prompt_input("Choose action: [1] Configure a new profile, [2] Login to an existing profile: ")

    profile_name_for_export = ""
    login_successful = False
    profile_to_login = ""

    if action == "1":
        # Use provided arguments or defaults for action 1
        sso_start_url_input = args.start_url
        sso_region_input = args.region

        print(f"Using start URL: {sso_start_url_input}", file=sys.stderr)
        print(f"Using region: {sso_region_input}", file=sys.stderr)

        token = get_sso_token(sso_start_url_input, sso_region_input)
        if token:
            new_profile_name = configure_profile(sso_start_url_input, sso_region_input, token)
            if new_profile_name:
                profile_name_for_export = new_profile_name
                login_successful = sso_login(new_profile_name)

    elif action == "2":
        # Use --profile argument, AWS_PROFILE env var, or prompt user
        profile_to_login = args.profile

        if not profile_to_login:
            profile_to_login = os.environ.get("AWS_PROFILE")

        if not profile_to_login:
            profile_to_login = prompt_input("Enter the name of the profile to log in to: ")
        else:
            print(f"Using profile: {profile_to_login}", file=sys.stderr)

        profile_name_for_export = profile_to_login
        login_successful = sso_login(profile_to_login)
    else:
        print("Invalid selection.", file=sys.stderr)

    if login_successful and not args.no_env:
        print(f'Setting up profile environment variable: "AWS_PROFILE={profile_to_login}"', file=sys.stderr)
        print(f"export AWS_PROFILE={profile_name_for_export}")

if __name__ == "__main__":
    main()