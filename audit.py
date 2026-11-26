
import os
import platform
import subprocess
import json
from datetime import datetime


# ==========================================
# Linux Hardening Audit Tool
# Author: Aritra Pal
# ==========================================


def run_command(command):
    """Run a Linux command safely and return its output."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip()

    except FileNotFoundError:
        return "Command not installed"

    except subprocess.TimeoutExpired:
        return "Command timed out"

    except Exception as error:
        return str(error)


# ==========================================
# 1. Firewall Audit
# ==========================================

def check_firewall():
    """Check UFW firewall status."""

    output = run_command(["ufw", "status"])

    if "Status: active" in output:
        return "PASS - Firewall is active"

    elif "Status: inactive" in output:
        return "WARNING - Firewall is inactive"

    else:
        return "INFO - UFW status unavailable"


# ==========================================
# 2. SSH Security Audit
# ==========================================

def check_ssh():
    """Check SSH root login configuration."""

    config_file = "/etc/ssh/sshd_config"

    if not os.path.exists(config_file):
        return "INFO - SSH configuration not found"

    try:
        with open(config_file, "r") as file:
            lines = file.readlines()

        for line in lines:
            line = line.strip()

            # Ignore comments
            if line.startswith("#") or not line:
                continue

            if line.lower().startswith("permitrootlogin"):
                setting = line.split()[-1].lower()

                if setting == "no":
                    return "PASS - Root SSH login disabled"

                else:
                    return "WARNING - Review root SSH login setting"

        return "INFO - Root SSH setting not explicitly configured"

    except PermissionError:
        return "INFO - Permission denied reading SSH config"


# ==========================================
# 3. Sensitive File Permission Audit
# ==========================================

def check_file_permissions():
    """Check permissions of sensitive system files."""

    files = [
        "/etc/passwd",
        "/etc/shadow"
    ]

    results = []

    for file_path in files:

        if os.path.exists(file_path):

            permissions = oct(
                os.stat(file_path).st_mode & 0o777
            )[-3:]

            results.append(
                f"{file_path}: permissions {permissions}"
            )

        else:
            results.append(
                f"{file_path}: file not found"
            )

    return results


# ==========================================
# 4. Security Score and Recommendations
# ==========================================

def calculate_security_score(report):
    """Calculate a basic educational security score."""

    score = 100
    recommendations = []

    # Firewall check
    if "WARNING" in report["firewall"]:
        score -= 20

        recommendations.append(
            "Enable and configure the firewall."
        )

    elif "INFO" in report["firewall"]:
        score -= 10

        recommendations.append(
            "Verify firewall installation and status."
        )

    # SSH check
    if "WARNING" in report["ssh"]:
        score -= 20

        recommendations.append(
            "Review SSH root login configuration."
        )

    elif "INFO" in report["ssh"]:
        score -= 10

        recommendations.append(
            "Review SSH configuration manually."
        )

    # File permission check
    for result in report["file_permissions"]:

        if "/etc/shadow" in result:

            if "permissions" in result:

                permission = result.split()[-1]

                if permission not in ["640", "600"]:
                    score -= 20

                    recommendations.append(
                        "Review /etc/shadow permissions."
                    )

            else:
                score -= 10

                recommendations.append(
                    "Verify /etc/shadow file availability."
                )

    score = max(score, 0)

    return score, recommendations


# ==========================================
# 5. Generate Audit Report
# ==========================================

def generate_report():
    """Collect audit results and generate reports."""

    report = {
        "project": "Linux Hardening Audit Tool",
        "author": "Aritra Pal",
        "date": str(datetime.now()),
        "system": platform.system(),
        "release": platform.release(),
        "firewall": check_firewall(),
        "ssh": check_ssh(),
        "file_permissions": check_file_permissions()
    }

    # Calculate security score
    score, recommendations = calculate_security_score(report)

    report["security_score"] = score
    report["recommendations"] = recommendations

    # Create reports folder
    os.makedirs("reports", exist_ok=True)

    # --------------------------------------
    # Save JSON Report
    # --------------------------------------

    with open(
        "reports/audit_report.json",
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    # --------------------------------------
    # Save Text Report
    # --------------------------------------

    with open(
        "reports/audit_report.txt",
        "w"
    ) as file:

        file.write(
            "LINUX HARDENING AUDIT REPORT\n"
        )

        file.write("=" * 35 + "\n\n")

        file.write(
            f"PROJECT: {report['project']}\n"
        )

        file.write(
            f"AUTHOR: {report['author']}\n"
        )

        file.write(
            f"DATE: {report['date']}\n"
        )

        file.write(
            f"SYSTEM: {report['system']}\n"
        )

        file.write(
            f"RELEASE: {report['release']}\n\n"
        )

        file.write(
            f"FIREWALL: {report['firewall']}\n"
        )

        file.write(
            f"SSH: {report['ssh']}\n\n"
        )

        file.write("FILE PERMISSIONS:\n")

        for result in report["file_permissions"]:
            file.write(f"- {result}\n")

        file.write(
            f"\nSECURITY SCORE: {score}/100\n"
        )

        file.write("\nRECOMMENDATIONS:\n")

        if recommendations:

            for recommendation in recommendations:
                file.write(
                    f"- {recommendation}\n"
                )

        else:
            file.write(
                "- No recommendations from these checks.\n"
            )

    # --------------------------------------
    # Display Results in Terminal
    # --------------------------------------

    print("\n")
    print("=" * 40)
    print(" LINUX HARDENING AUDIT TOOL")
    print("=" * 40)

    print(f"Author: {report['author']}")
    print(f"System: {report['system']}")
    print(f"Firewall: {report['firewall']}")
    print(f"SSH: {report['ssh']}")

    print("\nFile Permissions:")

    for result in report["file_permissions"]:
        print("-", result)

    print("\nSecurity Score:", score, "/100")

    print("\nRecommendations:")

    if recommendations:

        for recommendation in recommendations:
            print("-", recommendation)

    else:
        print("No recommendations from these checks.")

    print("\nAudit completed successfully!")

    print(
        "Reports saved inside the reports folder."
    )

    print("=" * 40)


# ==========================================
# 6. Main Program
# ==========================================

if __name__ == "__main__":
    generate_report()

