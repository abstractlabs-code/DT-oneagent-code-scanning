import os
import logging
import subprocess
import json
import time
import zipfile
from pathlib import Path
from atlassian import Confluence

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

BASE_DOWNLOAD_DIR = "/opt/oneagent/versions"
CLAMAV_REPORTS_DIR = "/opt/oneagent/clamav-reports"
MAX_RETRIES = 3
RETRY_DELAY = 3  

CONFLUENCE_BASE_URL = os.getenv("CONFLUENCE_BASE_URL")
CONFLUENCE_USERNAME = os.getenv("CONFLUENCE_USERNAME")
CONFLUENCE_API_TOKEN = os.getenv("CONFLUENCE_API_TOKEN")
CONFLUENCE_PAGE_ID = os.getenv("CONFLUENCE_PAGE_ID")

def get_available_versions():
    """Fetches all available OneAgent versions using curl."""
    dt_api_url = os.getenv("DT_API_URL", "").rstrip("/")
    dt_paas_token = os.getenv("DT_PAAS_TOKEN")

    if not all([dt_api_url, dt_paas_token]):
        logger.error("Missing required environment variables: DT_API_URL, DT_PAAS_TOKEN")
        return []

    url = f"{dt_api_url}/api/v1/deployment/installer/agent/versions/unix/paas?flavor=multidistro&arch=all"
    command = [
        "curl", "-s", "-X", "GET", url,
        "-H", "accept: application/json",
        "-H", f"Authorization: Api-Token {dt_paas_token}"
    ]

    for attempt in range(1, MAX_RETRIES + 1):
        logger.info(f"Fetching available OneAgent versions (Attempt {attempt}/{MAX_RETRIES})...")

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)
                if "availableVersions" in data and isinstance(data["availableVersions"], list):
                    versions = data["availableVersions"]
                    if versions:
                        logger.info(f"Retrieved {len(versions)} versions.")
                        return versions
                    else:
                        logger.error("API returned an empty version list.")
                else:
                    logger.error(f"Unexpected API response format: {data}")
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON response:\n{result.stdout}")
        else:
            logger.error(f"API request failed (Attempt {attempt}): {result.stderr or 'Empty response'}")

        if attempt < MAX_RETRIES:
            logger.info(f"Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)

    logger.error("Max retries reached. Unable to fetch versions.")
    return []

def download_oneagent(version):
    """Downloads OneAgent installer for a given version using curl and places it inside the version folder."""
    dt_api_url = os.getenv("DT_API_URL", "").rstrip("/")
    dt_paas_token = os.getenv("DT_PAAS_TOKEN")
    output_dir = Path(BASE_DOWNLOAD_DIR) / version

    if output_dir.exists() and any(output_dir.iterdir()):
        logger.info(f"Version {version} already exists. Skipping download.")
        return

    logger.info(f"Downloading OneAgent version {version}...")

    url = f"{dt_api_url}/api/v1/deployment/installer/agent/unix/paas/version/{version}?flavor=multidistro&arch=all&bitness=all&include=all&skipMetadata=false"
    
    output_dir.mkdir(parents=True, exist_ok=True)  

    command = [
        "curl", "-s", "-X", "GET", url,
        "-H", "accept: application/octet-stream",
        "-H", f"Authorization: Api-Token {dt_paas_token}",
        "-J", "-O", "--output-dir", str(output_dir)  
    ]

    result = subprocess.run(command)
    if result.returncode == 0:
        logger.info(f"Download successful for version {version}. File placed in {output_dir}")
        extract_files(output_dir)  
    else:
        logger.error(f"Failed to download version {version}")

def extract_files(version_dir):
    """Extracts any ZIP or SH file inside the version directory."""
    for file in version_dir.iterdir():
        if file.suffix == ".zip":
            extract_zip(file, version_dir)
        elif file.suffix == ".sh":
            extract_sh(file, version_dir)

def extract_zip(zip_path, extract_to):
    """Extracts a ZIP archive and removes it after extraction."""
    logger.info(f"Extracting ZIP file: {zip_path}")

    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            archive.extractall(extract_to)
        logger.info(f"Extraction successful: {extract_to}")
        zip_path.unlink()  
    except zipfile.BadZipFile as zip_err:
        logger.error(f"Failed to extract {zip_path}: {zip_err}")

def extract_sh(sh_path, extract_to):
    """Runs a shell script to self-extract the OneAgent installer."""
    logger.info(f"Executing self-extracting shell script: {sh_path}")

    try:
        subprocess.run(["bash", str(sh_path), "--unpack-dir", str(extract_to)], check=True)
        logger.info(f"Self-extraction successful: {extract_to}")
        sh_path.unlink()  
    except subprocess.CalledProcessError as sh_err:
        logger.error(f"Failed to execute {sh_path}: {sh_err}")

def update_clamav_database():
    """Updates the ClamAV database using freshclam."""
    logger.info("Updating ClamAV database using freshclam...")
    update_command = ["freshclam"]
    update_result = subprocess.run(update_command, capture_output=True, text=True)

    if update_result.returncode != 0:
        logger.error(f"Failed to update ClamAV database: {update_result.stderr}")
        return False

    logger.info("ClamAV database update completed successfully.")
    return True
    

def run_clamav_scan(version):
    """Runs a ClamAV scan only if a report does not already exist."""
    report_file = Path(CLAMAV_REPORTS_DIR) / f"oneagent-version-{version}-clamav_report.txt"

    if report_file.exists():
        logger.info(f"Skipping ClamAV scan: Report already exists for version {version}.")
        return report_file

    version_dir = Path(BASE_DOWNLOAD_DIR) / version
    if not version_dir.exists():
        logger.error(f"Skipping ClamAV scan: Version directory {version_dir} does not exist.")
        return None

    Path(CLAMAV_REPORTS_DIR).mkdir(parents=True, exist_ok=True)

    logger.info(f"Running ClamAV scan for version {version}...")

    with open(report_file, "w") as report:
        scan_command = ["clamscan", "-r", "--verbose", str(version_dir)]
        subprocess.run(scan_command, stdout=report, text=True)

    logger.info(f"ClamAV scan completed for version {version}. Report saved in {report_file}")
    return report_file

def upload_report_to_confluence(report_file):
    """Uploads the ClamAV report to Confluence, overwriting any existing report."""
    confluence = Confluence(
        url=CONFLUENCE_BASE_URL,
        username=CONFLUENCE_USERNAME,
        password=CONFLUENCE_API_TOKEN
    )

    logger.info(f"Uploading {report_file} to Confluence...")
    with open(report_file, "rb") as file:
        response = confluence.attach_file(
            filename=report_file.name,
            page_id=CONFLUENCE_PAGE_ID,
            file=file,
            replace=True  
        )

    if response:
        logger.info(f"Report {report_file.name} uploaded successfully to Confluence.")
    else:
        logger.error(f"Failed to upload report {report_file.name}.")

def main():
    update_clamav_database()
    versions = get_available_versions()
    for version in versions:
        download_oneagent(version)
        report_file = run_clamav_scan(version)
        if report_file:
            upload_report_to_confluence(report_file)

if __name__ == "__main__":
    main()
