import os
import logging
import subprocess
import json
import time
import zipfile
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

BASE_DOWNLOAD_DIR = "/opt/oneagent/versions"
CLAMAV_REPORTS_DIR = "/opt/oneagent/clamav-reports"
MAX_RETRIES = 3
RETRY_DELAY = 3  

def get_available_versions():
    """Fetches all available OneAgent versions using curl."""
    dt_api_url = os.getenv("DT_API_URL", "").rstrip("/")  # Ensure no trailing slash
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

def run_clamav_scan(version):
    """Runs a full ClamAV scan on a specific OneAgent version directory and saves the entire report."""
    version_dir = Path(BASE_DOWNLOAD_DIR) / version
    report_dir = Path(CLAMAV_REPORTS_DIR) / f"oneagent-{version}"
    report_file = report_dir / "clamav_report.txt"

    if not version_dir.exists():
        logger.error(f"Skipping ClamAV scan: Version directory {version_dir} does not exist.")
        return

    report_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Running ClamAV scan for version {version}...")

    command = ["clamscan", "-v", "-r", str(version_dir)]
    
    with open(report_file, "w") as report:
        result = subprocess.run(command, stdout=report, text=True)

    if result.returncode == 0:
        logger.info(f"ClamAV scan completed for version {version}. Full report saved in {report_file}")
    else:
        logger.error(f"ClamAV scan failed for version {version}. Check {report_file} for details.")

def main():
    versions = get_available_versions()
    if not versions:
        logger.error("No versions available for download. Exiting.")
        return

    for version in versions:
        download_oneagent(version)
    
    logger.info("All downloads completed. Running ClamAV scans...")
    
    for version in versions:
        run_clamav_scan(version)

if __name__ == "__main__":
    main()
