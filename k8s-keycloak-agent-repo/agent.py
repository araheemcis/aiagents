import os
import time
import io
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.header import decode_header
import urllib3
import pandas as pd
from kubernetes import client, config
from keycloak import KeycloakAdmin

# Suppress unverified HTTPS request warnings when verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# Environment Configuration
# ==============================================================================
GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "https://keycloak.keycloak.svc.cluster.local:8443/")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASS = os.getenv("KEYCLOAK_ADMIN_PASS")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "k8s-realm")

# Self-Service Onboarding URLs & OIDC Settings
KEYCLOAK_OIDC_URL = os.getenv("KEYCLOAK_OIDC_URL", "https://192.168.1.225:30281/realms/k8s-realm")
K8S_APISERVER_URL = os.getenv("K8S_APISERVER_URL", "https://192.168.1.225:6443")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "kubernetes")

DEFAULT_TEMP_PASSWORD = os.getenv("DEFAULT_TEMP_PASSWORD", "InitialTempPass123!")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
EMAIL_SUBJECT_FILTER = os.getenv("EMAIL_SUBJECT_FILTER", "K8s user deployment")


# ==============================================================================
# Helper Functions
# ==============================================================================
def get_keycloak_admin_client():
    """Instantiate a fresh KeycloakAdmin client to avoid session token expiration."""
    return KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USER,
        password=KEYCLOAK_ADMIN_PASS,
        realm_name=KEYCLOAK_REALM,
        user_realm_name="master",
        verify=False
    )


def send_email(to_email, subject, body):
    """Generic SMTP dispatcher for summary replies and user notifications."""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = GMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, [to_email], msg.as_string())
        print(f"[+] Email successfully sent to {to_email}")
    except Exception as e:
        print(f"[-] Failed to send email to {to_email}: {e}")


def k8s_group_exists(rbac_api, group_name):
    """
    Check if a ClusterRoleBinding or RoleBinding matches group_name or oidc:group_name.
    Safely handles NoneType subjects and RBAC API inspection errors.
    """
    candidate_names = {group_name, f"oidc:{group_name}"}

    try:
        # 1. Check ClusterRoleBindings
        crbs = rbac_api.list_cluster_role_binding()
        for crb in crbs.items:
            if crb.subjects is not None:
                for subj in crb.subjects:
                    if (
                        getattr(subj, 'kind', None) == "Group"
                        and getattr(subj, 'name', None) in candidate_names
                    ):
                        print(f"[+] Found K8s ClusterRoleBinding subject match: {subj.name}")
                        return True

        # 2. Check RoleBindings across all namespaces
        rbs = rbac_api.list_role_binding_for_all_namespaces()
        for rb in rbs.items:
            if rb.subjects is not None:
                for subj in rb.subjects:
                    if (
                        getattr(subj, 'kind', None) == "Group"
                        and getattr(subj, 'name', None) in candidate_names
                    ):
                        print(f"[+] Found K8s RoleBinding subject match in ns '{rb.metadata.namespace}': {subj.name}")
                        return True

    except Exception as e:
        print(f"[-] K8s RBAC API inspection error for group '{group_name}': {e}")
        return False

    return False


# ==============================================================================
# Core Processing Logic
# ==============================================================================
def process_excel_attachment(file_bytes, rbac_api, sender_email, subject):
    """Parse Excel spreadsheet, provision Keycloak/K8s objects, and dispatch emails."""
    df = pd.read_excel(io.BytesIO(file_bytes))
    results = []

    try:
        keycloak_admin = get_keycloak_admin_client()
    except Exception as e:
        err_msg = f"FAILED: Could not connect to Keycloak Admin API: {e}"
        print(f"[-] {err_msg}")
        send_email(sender_email, f"Re: {subject}", err_msg)
        return

    for _, row in df.iterrows():
        username = str(row['username']).strip()
        group_name = str(row['group_name']).strip()
        user_email = str(row.get('email', f"{username}@example.com")).strip()

        print(f"[*] Processing user '{username}' for group '{group_name}'...")

        # 1. Validate K8s RBAC existence
        if not k8s_group_exists(rbac_api, group_name):
            err_msg = (
                f"FAILED: Group '{group_name}' (or 'oidc:{group_name}') requested for user '{username}' "
                f"does NOT exist in Kubernetes RBAC."
            )
            print(f"[-] {err_msg}")
            results.append(err_msg)
            continue

        # 2. Keycloak Operations
        try:
            # Check/Create Keycloak Group
            groups = keycloak_admin.get_groups()
            kc_group = next((g for g in groups if g['name'] == group_name), None)
            if not kc_group:
                group_id = keycloak_admin.create_group({"name": group_name})
                print(f"[+] Created Keycloak group '{group_name}'")
            else:
                group_id = kc_group['id']

            # Check/Create Keycloak User
            user_id = keycloak_admin.get_user_id(username)
            if not user_id:
                user_id = keycloak_admin.create_user({
                    "username": username,
                    "email": user_email,
                    "enabled": True,
                    "credentials": [{
                        "type": "password",
                        "value": DEFAULT_TEMP_PASSWORD,
                        "temporary": True
                    }]
                })
                print(f"[+] Created Keycloak user '{username}' ({user_email})")
            else:
                print(f"[*] Keycloak user '{username}' already exists. Assigning to group...")

            # Assign User to Group
            keycloak_admin.group_user_add(user_id, group_id)

            success_msg = (
                f"SUCCESS: User '{username}' ({user_email}) created/updated and assigned to group '{group_name}'. "
                f"[Temp Password: {DEFAULT_TEMP_PASSWORD}]"
            )
            print(f"[+] {success_msg}")
            results.append(success_msg)

            # 3. Construct Kubeconfig Template
            kubeconfig_template = f"""apiVersion: v1
clusters:
- cluster:
    server: {K8S_APISERVER_URL}
  name: k8s-cluster
contexts:
- context:
    cluster: k8s-cluster
    user: {username}
  name: k8s-cluster-{username}
current-context: k8s-cluster-{username}
kind: Config
preferences: {{}}
users:
- name: {username}
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url={KEYCLOAK_OIDC_URL}
      - --oidc-client-id={OIDC_CLIENT_ID}
"""

            # 4. Dispatch Welcome Email
            user_subject = "Your Kubernetes / Keycloak Account & Cluster Access Details"
            user_body = f"""Hello {username},

Your account has been successfully provisioned for Kubernetes group '{group_name}'.

======================================================================
1. ACCOUNT CREDENTIALS & SSO LOGIN
======================================================================
- Username:           {username}
- Email:              {user_email}
- Assigned Group:     {group_name}
- Temporary Password: {DEFAULT_TEMP_PASSWORD}

OIDC Login Portal:
{KEYCLOAK_OIDC_URL}/account

First-Time Setup:
1. Open the OIDC Login Portal URL above in your browser.
2. Log in using your username and temporary password.
3. Update your temporary password to a permanent one when prompted.

======================================================================
2. KUBERNETES KUBECONFIG SETUP
======================================================================
To access the cluster via `kubectl`, copy the configuration block below 
and save it to your local kubeconfig file (~/.kube/config or %USERPROFILE%\\.kube\\config):

----------------------------- START CONFIG -----------------------------
{kubeconfig_template}------------------------------ END CONFIG ------------------------------

======================================================================
3. HOW TO AUTHENTICATE VIA KUBECTL
======================================================================
Prerequisite: Ensure 'kubelogin' (OIDC plugin) is installed:
  - macOS:   brew install int128/kubelogin/kubelogin
  - Windows: choco install kubelogin

To authenticate and verify cluster access, run:
  kubectl get pods

This command will automatically open your default browser to authenticate 
with Keycloak and issue your cluster access token.

Best regards,
K8s Automated Provisioning System
"""
            send_email(user_email, user_subject, user_body)

        except Exception as e:
            err_msg = f"FAILED: Error processing user '{username}': {e}"
            print(f"[-] {err_msg}")
            results.append(err_msg)

    # 5. Send Executive Summary Email
    reply_subject = f"Re: {subject}" if not subject.startswith("Re:") else subject
    summary_body = (
        "K8s OIDC Provisioning Execution Summary:\n\n"
        + "\n".join(results)
        + f"\n\nNote: Individual welcome emails containing temporary passwords ({DEFAULT_TEMP_PASSWORD}), "
          f"OIDC portal links, and personalized kubeconfig templates have been dispatched to all users."
    )
    send_email(sender_email, reply_subject, summary_body)


# ==============================================================================
# Main Polling Loop
# ==============================================================================
def poll_inbox():
    print("[*] Starting K8s Keycloak Provisioning Agent v2.2.0...")

    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    rbac_api = client.RbacAuthorizationV1Api()

    while True:
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            mail.select("inbox")

            search_query = f'(UNSEEN SUBJECT "{EMAIL_SUBJECT_FILTER}")'
            status, messages = mail.search(None, search_query)
            if status == "OK":
                for num in messages[0].split():
                    if not num:
                        continue
                    _, data = mail.fetch(num, "(RFC822)")
                    raw_email = data[0][1]
                    msg = email.message_from_bytes(raw_email)

                    sender_email = email.utils.parseaddr(msg.get("From"))[1]
                    subject_header = msg.get("Subject")
                    subject, encoding = decode_header(subject_header)[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8")

                    print(f"[+] Found unread request email from {sender_email}")

                    for part in msg.walk():
                        if part.get_content_maintype() == "multipart":
                            continue
                        if part.get("Content-Disposition") is None:
                            continue

                        filename = part.get_filename()
                        if filename and (filename.endswith(".xlsx") or filename.endswith(".xls")):
                            print(f"[+] Attachment detected: {filename}")
                            file_bytes = part.get_payload(decode=True)
                            process_excel_attachment(file_bytes, rbac_api, sender_email, subject)

            mail.logout()
        except Exception as e:
            print(f"[-] Error in poll loop: {e}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    poll_inbox()