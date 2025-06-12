# JFrog Port Integration Script
# 
# This script synchronizes JFrog Artifactory and Xray data with Port's developer portal.
# It imports repositories, builds, projects, container images, and security vulnerabilities.
#
# PREREQUISITES:
# - Python 3.7+
# - JFrog Artifactory with Xray integration
# - Port account with API access
# - JFrog Access Token with appropriate permissions
#
# SETUP:
# 1. Install dependencies: pip install python-dotenv requests
# 2. Create .env file with required credentials:
#    PORT_CLIENT_ID=your_port_client_id
#    PORT_CLIENT_SECRET=your_port_client_secret
#    JFROG_ACCESS_TOKEN=your_jfrog_access_token
#    JFROG_HOST_URL=https://your-instance.jfrog.io
# 3. Import Port blueprints from provided JSON files:
#    - jfrog-projects.json
#    - jfrog-container-vulns.json
#    - jfrog-baseimage-vulns.json
#    - jfrog-repository.json
#    - jfrog-build.json
#    - jfrog-project.json
#    - jfrog-container-image.json
#
# USAGE:
# python jfrog-script.py
#
# The script will:
# 1. Sync JFrog repositories to Port
# 2. Sync JFrog builds to Port
# 3. Sync JFrog projects with roles to Port
# 4. Discover and sync container images to Port
# 5. Scan images for vulnerabilities and sync to Port

# Dependencies to install
# pip install python-dotenv
# pip install requests

import logging
import os
import time
from datetime import datetime

import dotenv
import requests

dotenv.load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PORT_API_URL = "https://api.getport.io/v1"
PORT_CLIENT_ID = os.getenv("PORT_CLIENT_ID")
PORT_CLIENT_SECRET = os.getenv("PORT_CLIENT_SECRET")
JFROG_ACCESS_TOKEN = os.getenv("JFROG_ACCESS_TOKEN")
JFROG_HOST_URL = os.getenv("JFROG_HOST_URL")


class Blueprint:
    REPOSITORY = "jfrogRepository"
    BUILD = "jfrogBuild"
    PROJECT = "jfrogProject"
    CONTAINER_IMAGE = "containerImage"
    CONTAINER_VULNERABILITY = "containerVulnerability"


## Get Port Access Token
credentials = {"clientId": PORT_CLIENT_ID, "clientSecret": PORT_CLIENT_SECRET}
token_response = requests.post(f"{PORT_API_URL}/auth/access_token", json=credentials)
access_token = token_response.json()["accessToken"]

# You can now use the value in access_token when making further requests
headers = {"Authorization": f"Bearer {access_token}"}


def add_entity_to_port(blueprint_id, entity_object, transform_function):
    """A function to create the passed entity in Port

    Params
    --------------
    blueprint_id: str
        The blueprint id to create the entity in Port

    entity_object: dict
        The entity to add in your Port catalog

    transform_function: function
        A function to transform the entity object to the Port entity object

    Returns
    --------------
    response: dict
        The response object after calling the webhook
    """
    logger.info(f"Adding entity to Port: {entity_object}")
    entity_payload = transform_function(entity_object)
    response = requests.post(
        (
            f"{PORT_API_URL}/blueprints/"
            f"{blueprint_id}/entities?upsert=true&merge=true"
        ),
        json=entity_payload,
        headers=headers,
    )
    logger.info(response.json())


def get_all_builds():
    logger.info("Getting all builds")
    url = f"{JFROG_HOST_URL}/artifactory/api/build"
    try:
        response = requests.get(
            url, headers={"Authorization": "Bearer " + JFROG_ACCESS_TOKEN}
        )
        response.raise_for_status()
        builds = response.json()["builds"]
        return builds
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching JFrog builds: {e}")
        return []


def get_all_repositories():
    logger.info("Getting all repositories")
    url = f"{JFROG_HOST_URL}/artifactory/api/repositories"
    try:
        response = requests.get(
            url, headers={"Authorization": "Bearer " + JFROG_ACCESS_TOKEN}
        )
        response.raise_for_status()
        repositories = response.json()
        return repositories
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching JFrog repositories: {e}")
        return []

def get_all_projects():
    logger.info("Getting all projects")
    url = f"{JFROG_HOST_URL}/access/api/v1/projects"
    try:
        response = requests.get(
            url, headers={"Authorization": "Bearer " + JFROG_ACCESS_TOKEN}
        )
        response.raise_for_status()
        projects = response.json()
        return projects
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching JFrog projects: {e}")
        return []

def get_project_roles(project_key):
    """Get roles associated with a specific JFrog project"""
    logger.info(f"Getting roles for project: {project_key}")
    url = f"{JFROG_HOST_URL}/access/api/v1/projects/{project_key}/roles"
    try:
        response = requests.get(
            url, headers={"Authorization": "Bearer " + JFROG_ACCESS_TOKEN}
        )
        response.raise_for_status()
        roles = response.json()
        return roles
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching roles for project {project_key}: {e}")
        return []


def get_container_images():
    """Get all container images from Docker repositories"""
    logger.info("Getting container images from Docker repositories")
    
    repositories = get_all_repositories()
    docker_repos = [repo for repo in repositories if repo.get("packageType", "").lower() == "docker"]
    
    container_images = []
    
    for repo in docker_repos:
        repo_key = repo["key"]
        catalog_url = f"{JFROG_HOST_URL}/artifactory/api/docker/{repo_key}/v2/_catalog"
        try:
            catalog_resp = requests.get(catalog_url, headers={"Authorization": "Bearer " + JFROG_ACCESS_TOKEN})
            if catalog_resp.status_code == 404: # a V1 repo might not have a catalog
                 logger.warning(f"Could not find catalog for repo {repo_key}, skipping.")
                 continue
            catalog_resp.raise_for_status()
            images_in_repo = catalog_resp.json().get("repositories", [])
            
            for image_name in images_in_repo:
                tags_url = f"{JFROG_HOST_URL}/artifactory/api/docker/{repo_key}/v2/{image_name}/tags/list"
                tags_resp = requests.get(tags_url, headers={"Authorization": "Bearer " + JFROG_ACCESS_TOKEN})
                if tags_resp.status_code == 404:
                    logger.warning(f"Could not find tags for image {image_name} in repo {repo_key}, skipping.")
                    continue
                tags_resp.raise_for_status()
                tags_data = tags_resp.json()
                
                tags = tags_data.get("tags")
                if not tags:
                    continue

                for tag in tags:
                    image_data = {
                        "name": image_name,
                        "tag": tag,
                        "repository": repo_key,
                        "fullName": f"{repo_key}/{image_name}:{tag}"
                    }
                    container_images.append(image_data)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error processing repo {repo_key}: {e}")
            continue

    return container_images


def get_container_manifest_path(image_data):
    """Get the SHA256 hash for a container image using the dependency graph API"""
    logger.info(f"Getting SHA256 hash for: {image_data['fullName']}")
    
    # Construct the base path for the image tag
    base_path = f"default/{image_data['repository']}/{image_data['name']}/{image_data['tag']}"
    
    # Use the dependency graph API to get the SHA256
    url = f"{JFROG_HOST_URL}/xray/api/v1/dependencyGraph/artifact"
    payload = {
        "path": f"{base_path}"
    }
    
    logger.info(f"Using path for dependency graph: {base_path}")
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers={
                "Authorization": "Bearer " + JFROG_ACCESS_TOKEN,
                "Content-Type": "application/json"
            }
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract SHA256 from the response
        if "artifact" in data and "sha256" in data["artifact"]:
            sha256 = data["artifact"]["sha256"]
            logger.info(f"Found SHA256 hash: {sha256}")
            return sha256
            
        
        logger.warning(f"No SHA256 hash found in dependency graph response for {image_data['fullName']}")
        return None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting SHA256 hash for {image_data['fullName']}: {e}")
        return None


def get_component_vulnerabilities(image_data):
    """Get vulnerabilities for a specific component"""
    logger.info(f"Getting vulnerabilities for component: {image_data['fullName']}")
    
    # Get the SHA256 hash
    sha256_hash = get_container_manifest_path(image_data)
    
    if not sha256_hash:
        logger.warning(f"Could not get SHA256 hash for {image_data['fullName']}, skipping vulnerability scan")
        return []
    
    url = f"{JFROG_HOST_URL}/xray/api/v1/summary/artifact"
    payload = {
        "checksums": [sha256_hash]
    }
    
    logger.info(f"Using SHA256 hash for vulnerability scan: {sha256_hash}")
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers={
                "Authorization": "Bearer " + JFROG_ACCESS_TOKEN,
                "Content-Type": "application/json"
            }
        )
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = []
        if not data.get("artifacts"):
            if data.get("errors"):
                logger.warning(f"Could not fetch vulnerabilities for {image_data['fullName']}: {data['errors'][0]['error']}")
            return []

        artifact = data["artifacts"][0]
        artifact_general = artifact.get("general", {})
        
        for issue in artifact.get("issues", []):
            for cve in issue.get("cves", []):
                
                # Extract only the fields present in the simplified blueprint
                vulnerability_obj = {
                    # Core vulnerability info (required fields)
                    "cve": cve.get("cve", ""),
                    "severity": issue.get("severity", "Unknown"),
                    "status": "Open",  # Default status
                    "component": artifact_general.get("name", image_data.get("name", "Unknown")),
                    "imageName": image_data["fullName"],
                    "created": issue.get("created"),
                    
                    # Additional fields from blueprint
                    "cwe": cve.get("cwe", []),  # CWE identifiers as array
                    "imageTag": image_data["tag"],
                    "description": issue.get("description", ""),
                    "summary": issue.get("summary", ""),
                    "cvssScore": cve.get("cvss_v3_score") or cve.get("cvss_v2_score"),
                    "issueId": issue.get("issue_id", ""),
                    "provider": issue.get("provider", ""),
                    "artifactPath": artifact_general.get("path", ""),
                    "packageType": artifact_general.get("pkg_type", "")
                }
                
                # Clean up None values to avoid issues with Port
                vulnerability_obj = {k: v for k, v in vulnerability_obj.items() if v is not None}
                
                vulnerabilities.append(vulnerability_obj)
        
        return vulnerabilities
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching vulnerabilities for {image_data['fullName']}: {e}")
        return []


if __name__ == "__main__":
    logger.info("Starting Port integration")
    for repository in get_all_repositories():
        repository_object = {
            "key": repository["key"],
            "description": repository.get("description", ""),
            "type": repository["type"].upper(),
            "url": repository["url"],
            "packageType": repository["packageType"].upper(),
        }
        transform_build_function = lambda x: {
            "identifier": repository_object["key"],
            "title": repository_object["key"],
            "properties": {
                **repository_object,
            },
        }
        logger.info(f"Added repository: {repository_object['key']}")
        add_entity_to_port(
            Blueprint.REPOSITORY, repository_object, transform_build_function
        )

    logger.info("Completed repositories, starting builds")
    for build in get_all_builds():
        build_object = {
            "name": build["uri"].split("/")[-1],
            "uri": build["uri"],
            "lastStarted": build["lastStarted"],
        }
        transform_build_function = lambda x: {
            "identifier": build_object["name"],
            "title": build_object["name"],
            "properties": {
                **build_object,
            },
        }
        logger.info(f"Added build: {build_object['name']}")
        add_entity_to_port(Blueprint.BUILD, build_object, transform_build_function)
    
    logger.info("Completed builds, starting projects")
    for project in get_all_projects():
        project_key = project["project_key"]
        project_roles = get_project_roles(project_key)
        
        project_object = {
            "key": project_key,
            "name": project.get("display_name", ""),
            "description": project.get("description", ""),
            "adminPrivileges": project.get("admin_privileges", {}),
            "roles": project_roles
        }
        transform_project_function = lambda x: {
            "identifier": project_object["key"],
            "title": project_object["name"],
            "properties": {
                **project_object,
            },
        }
        logger.info(f"Added project: {project_object['name']}")
        add_entity_to_port(Blueprint.PROJECT, project_object, transform_project_function)
    
    logger.info("Completed projects, starting container images")
    all_container_images = get_container_images()
    for image in all_container_images:
        image_object = {
            "name": image["name"],
            "tag": image["tag"],
            "repository": image["repository"],
            "fullName": image["fullName"],
        }
        
        transform_image_function = lambda x: {
            "identifier": image_object["fullName"],
            "title": image_object["fullName"],
            "properties": {
                **image_object,
            },
        }
        logger.info(f"Added container image: {image_object['fullName']}")
        add_entity_to_port(Blueprint.CONTAINER_IMAGE, image_object, transform_image_function)
    
    logger.info("Completed container images, starting vulnerabilities scan")
    for image in all_container_images:
        vulnerabilities = get_component_vulnerabilities(image)
        for vuln in vulnerabilities:
            vuln_identifier = f"{image['fullName']}-{vuln['cve']}"
            transform_vuln_function = lambda x: {
                "identifier": vuln_identifier,
                "title": f"{vuln['cve']} in {image['fullName']}",
                "properties": {
                    **vuln
                },
                "relations": {
                    "containerImage": image["fullName"]
                }
            }
            logger.info(f"Adding vulnerability: {vuln['cve']} for image {image['fullName']}")
            add_entity_to_port(Blueprint.CONTAINER_VULNERABILITY, vuln, transform_vuln_function)

    logger.info("Port integration completed successfully")
