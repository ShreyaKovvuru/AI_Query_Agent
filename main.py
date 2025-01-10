from flask import Flask, request, jsonify
from pydantic import BaseModel, ValidationError
from kubernetes import client, config, watch
from dotenv import load_dotenv
from flask_cors import CORS
import openai
import logging
import re
import difflib
import subprocess 
import json
import os


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="agent.log",
    filemode="a"
)

app = Flask(__name__)
# CORS(app)


# Load Kubernetes configuration
try:
    config.load_kube_config(os.path.expanduser("~/.kube/config"))
except Exception as e:
    logging.error(f"Failed to load kubeconfig: {e}")

# Set the OpenAI API key from the environment variable
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")
# Check if the API key is not set
if not openai.api_key:
    print("Warning: OPENAI_API_KEY is not set. Ensure it is set during deployment.")


# Check if the API key is not set
#if not openai.api_key:
#    logging.error("OPENAI_API_KEY environment variable is not set.")
#    raise EnvironmentError("The OPENAI_API_KEY environment variable is required but not set.")


SUPPORTED_RESOURCES = [
    "pods", "services", "configmaps", "secrets", "deployments", "replicasets", 
    "statefulsets", "nodes", "persistentvolumes", "persistentvolumeclaims", 
    "events", "namespaces", "contexts"
]

SUPPORTED_ACTIONS = [
    "list", "count", "status", "delete", "apply", "describe", "logs", "watch", 
    "config_view", "version", "find_harbor_namespace", "count_pods", 
    "get_container_port", "get_status", "get_service_target_port", 
    "get_readiness_probe_path", "get_pods_using_secret", 
    "get_persistent_volume_mount_path", "get_env_variable", "get_database_info"
]

class QueryRequest(BaseModel):
    query:str

# Define the Pydantic model for response format
class QueryResponse(BaseModel):
    query: str
    answer: str


def clean_resource_name(name: str) -> str:
    """Simplify Kubernetes resource names by removing unique identifiers."""
    logging.info(f"Cleaned resource name")
    return re.sub(r"-[a-z0-9]{6,10}$", "", name)


def get_kubectl_events(namespace=None):
    try:
        # Build the kubectl command
        if namespace:
            command = ["kubectl", "get", "events", "-n", namespace, "-o", "wide"]
        else:
            command = ["kubectl", "get", "events", "--all-namespaces", "-o", "wide"]

        # Execute the command and capture output
        logging.info("Executing: %s", " ".join(command))
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            logging.error("Error fetching events: %s", result.stderr)
            return []

        # Split the output into lines and process each event
        events = result.stdout.strip().split("\n")
        logging.info("Fetched events successfully.")
        return events

    except Exception as e:
        logging.error(f"An error occurred while fetching events: {str(e)}")
        return []


def find_service_namespace(service_name: str):
    """
    Find the namespace for the given service by searching across all namespaces.
    """
    v1 = client.CoreV1Api()
    try:
        # List all services across all namespaces
        services = v1.list_service_for_all_namespaces()
        matching_services = [
            {"service_name": svc.metadata.name, "namespace": svc.metadata.namespace}
            for svc in services.items
            if service_name.lower() in svc.metadata.name.lower()
        ]
        if matching_services:
            return matching_services
        return f"No services matching '{service_name}' found in any namespace."
    except Exception as e:
        return f"Error finding service namespace: {str(e)}"



# def count_pods():
#     """Count the total number of pods in the cluster."""
#     v1 = client.CoreV1Api()
#     pods = v1.list_pod_for_all_namespaces().items
#     return len(pods)

def get_container_port(namespace, deployment_name):
    """Retrieve the container port for a specific deployment."""
    apps_v1 = client.AppsV1Api()
    deployment = apps_v1.read_namespaced_deployment(deployment_name, namespace)
    return deployment.spec.template.spec.containers[0].ports[0].container_port

def get_status(namespace, deployment_name):
    """Retrieve the status of a specific deployment."""
    apps_v1 = client.AppsV1Api()
    deployment = apps_v1.read_namespaced_deployment_status(deployment_name, namespace)
    return deployment.status.conditions[-1].type

def get_service_target_port(namespace, service_name):
    """Retrieve the target port for a specific service."""
    v1 = client.CoreV1Api()
    svc = v1.read_namespaced_service(service_name, namespace)
    return svc.spec.ports[0].target_port

def get_readiness_probe_path(namespace, deployment_name):
    """Retrieve the readiness probe path for a specific deployment."""
    apps_v1 = client.AppsV1Api()
    try:
        deployment = apps_v1.read_namespaced_deployment(deployment_name, namespace)
        return deployment.spec.template.spec.containers[0].readiness_probe.http_get.path
    except Exception as e:
        logging.error(f"Error retrieving readiness probe path: {e}")
        return f"Error retrieving readiness probe path: {e}"

def get_pods_using_secret(secret_name):
    """Find pods associated with a specific secret."""
    v1 = client.CoreV1Api()
    pods = v1.list_pod_for_all_namespaces().items
    result = []
    for pod in pods:
        for volume in pod.spec.volumes:
            if volume.secret and volume.secret.secret_name == secret_name:
                result.append(pod.metadata.name)
    return result

def get_persistent_volume_mount_path(namespace, deployment_name):
    """Retrieve the mount path of a persistent volume for a deployment."""
    apps_v1 = client.AppsV1Api()
    deployment = apps_v1.read_namespaced_deployment(deployment_name, namespace)
    return deployment.spec.template.spec.containers[0].volume_mounts[0].mount_path

def get_env_variable(namespace, pod_name, env_name):
    """Retrieve the value of an environment variable in a specific pod."""
    v1 = client.CoreV1Api()
    pod = v1.read_namespaced_pod(pod_name, namespace)
    for env in pod.spec.containers[0].env:
        if env.name == env_name:
            return env.value
    return "Not found"

# def get_database_name(namespace, secret_name):
#     """Retrieve the database name from a secret."""
#     v1 = client.CoreV1Api()
#     try:
#         # Retrieve the secret
#         secret = v1.read_namespaced_secret(secret_name, namespace)

#         # Iterate over all keys in the secret
#         for key, value in secret.data.items():
#             decoded_value = base64.b64decode(value).decode("utf-8")
            
#             # Check if the key contains a database name or connection string
#             if "db" in key.lower() or "connection" in key.lower():
#                 if "://" in decoded_value:  # Likely a connection string
#                     parsed_url = urlparse(decoded_value)
#                     database_name = parsed_url.path.lstrip("/")  # Extract database name
#                     if database_name:
#                         return database_name
#                 else:
#                     return decoded_value  # Direct database name
#         return "Database name not found in the secret."
#     except client.exceptions.ApiException as e:
#         logging.error(f"Kubernetes API exception: {e}")
#         return f"Error retrieving database name: {e.reason}"
#     except Exception as e:
#         logging.error(f"Unhandled exception: {e}")
#         return f"Error retrieving database name: {str(e)}"

def find_database_secrets(v1, namespace):
    """Find all database-related secrets in a namespace."""
    try:
        secrets = v1.list_namespaced_secret(namespace)
        db_secrets = []
        for secret in secrets.items:
            if any(db_term in secret.metadata.name.lower() 
                  for db_term in ['db', 'database', 'postgresql', 'mysql', 'postgres']):
                db_secrets.append(secret)
        return db_secrets
    except Exception as e:
        logging.error(f"Error finding database secrets: {e}")
        return []

def extract_database_info(secret_data, info_type="database_name"):
    """Extract database information from secret data."""
    try:
        for key, value in secret_data.items():
            decoded_value = base64.b64decode(value).decode('utf-8')
            
            # Check for connection strings
            if "://" in decoded_value:
                parsed_url = urlparse(decoded_value)
                if info_type == "database_name":
                    return parsed_url.path.lstrip('/')
                elif info_type == "credentials":
                    return {
                        "username": parsed_url.username,
                        "password": parsed_url.password
                    }
                elif info_type == "connection":
                    return decoded_value
            
            # Check for specific keys
            key_lower = key.lower()
            if info_type == "database_name" and any(term in key_lower 
                for term in ['database', 'dbname', 'db_name', 'postgres_db']):
                return decoded_value
            
            # Check env vars format
            if info_type == "database_name" and 'POSTGRES_DB' in key:
                return decoded_value
            
    except Exception as e:
        logging.error(f"Error extracting database info: {e}")
    return None
def get_database_info(v1, namespace, component=None, info_type="database_name"):
    """Get database information from Kubernetes resources."""
    try:
        # First try to find component-specific secrets
        secrets = find_database_secrets(v1, namespace)
        if not secrets:
            return "No database secrets found"

        for secret in secrets:
            # Try to extract information from each secret
            info = extract_database_info(secret.data, info_type)
            if info:
                return {
                    "secret_name": secret.metadata.name,
                    "database_info": info
                }

        # If no information found, try to get it from environment variables
        if component:
            pods = v1.list_namespaced_pod(namespace, label_selector=f"app={component}")
            for pod in pods.items:
                for container in pod.spec.containers:
                    for env in container.env:
                        if env.value_from and env.value_from.secret_key_ref:
                            secret_name = env.value_from.secret_key_ref.name
                            key = env.value_from.secret_key_ref.key
                            try:
                                secret = v1.read_namespaced_secret(secret_name, namespace)
                                if key in secret.data:
                                    value = base64.b64decode(secret.data[key]).decode('utf-8')
                                    return {
                                        "secret_name": secret_name,
                                        "database_info": value
                                    }
                            except Exception as e:
                                logging.error(f"Error reading secret {secret_name}: {e}")

        return "Database information not found"

    except Exception as e:
        logging.error(f"Error getting database info: {e}")
        return f"Error: {str(e)}"



def handle_kubernetes_action(action: str, resource: str = None, namespace: str = "default", name: str = None, file_path: str = None, output_format: str = None, watch_mode: bool = False, query_params: dict = None) -> str:
    logging.info(f"Handling Kubernetes action: action={action}, resource={resource}, namespace={namespace}, name={name}, file_path={file_path}, output_format={output_format}, watch_mode={watch_mode}")
    query_params = query_params or {} 
    try:
        # Initialize API clients
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()

        if action == "get_database_info":
            try:
                # First, find Harbor namespace
                harbor_namespace = None
                namespaces = v1.list_namespace()
                for ns in namespaces.items:
                    if "harbor" in ns.metadata.name.lower():
                        harbor_namespace = ns.metadata.name
                        break
                
                if not harbor_namespace:
                    return "Harbor namespace not found"

                logging.info(f"Found Harbor namespace: {harbor_namespace}")

                # Try to get the harbor-core secret
                try:
                    secret = v1.read_namespaced_secret("harbor-core", harbor_namespace)
                    logging.info("Found harbor-core secret")

                    # Look for database name in the secret data
                    search_terms = [
                        "POSTGRESQL_DATABASE",
                        "POSTGRES_DB",
                        "DB_NAME",
                        "DATABASE_NAME",
                        "HARBOR_DATABASE"
                    ]

                    for key in secret.data:
                        if any(term.lower() in key.lower() for term in search_terms):
                            db_name = base64.b64decode(secret.data[key]).decode('utf-8')
                            return f"Database name: {db_name}"

                    # If not found in direct keys, check for database connection string
                    connection_keys = [
                        "DATABASE_URL",
                        "HARBOR_DATABASE_URL",
                        "POSTGRESQL_HOST"
                    ]

                    for key in secret.data:
                        if any(term.lower() in key.lower() for term in connection_keys):
                            conn_str = base64.b64decode(secret.data[key]).decode('utf-8')
                            return f"Database connection: {conn_str}"

                    # If still not found, return all relevant keys for debugging
                    db_related_keys = [key for key in secret.data.keys() if 'db' in key.lower() or 'database' in key.lower()]
                    if db_related_keys:
                        return f"Found database-related keys: {', '.join(db_related_keys)}"

                    return "Database information not found in harbor-core secret"

                except client.exceptions.ApiException as e:
                    logging.error(f"Error accessing harbor-core secret: {e}")
                    return f"Error accessing harbor-core secret: {e.reason}"

            except Exception as e:
                logging.error(f"Error getting database info: {e}")
                return f"Error getting database info: {str(e)}"

        if action == "count" and resource == "pods":
            try:
                # Check if we need to count across all namespaces
                if namespace is None or query_params.get('all_namespaces', False):
                    logging.info("Counting pods across all namespaces")
                    pods = v1.list_pod_for_all_namespaces()
                    pod_count = len(pods.items)
                    
                    # Optional: Get count by namespace
                    pods_by_namespace = {}
                    for pod in pods.items:
                        ns = pod.metadata.namespace
                        pods_by_namespace[ns] = pods_by_namespace.get(ns, 0) + 1
                    
                    return {
                        "total_pods": pod_count,
                        "pods_by_namespace": pods_by_namespace
                    }
                else:
                    # Existing namespace-specific pod count logic
                    pods = v1.list_namespaced_pod(namespace)
                    return len(pods.items)
                    
            except client.exceptions.ApiException as e:
                logging.error(f"API Exception while counting pods: {e}")
                return f"Error counting pods: {e.reason}"
            except Exception as e:
                logging.error(f"Error counting pods: {e}")
                return f"Error counting pods: {str(e)}"

        # Find namespace for a specific service
        if action == "describe" and resource == "services" and output_format == "namespace":
            if name:
                return find_service_namespace(name)
            else:
                return "Service name is required to find its namespace."

        # Full description for a service
        if action == "describe" and resource == "services":
            if name and namespace:
                service = v1.read_namespaced_service(name=name, namespace=namespace)
                return service.to_dict()
            else:
                return "Both service name and namespace are required to describe a service."


        # if action == "count_pods":
        #     return count_pods()

        if action == "get_container_port":
            return get_container_port(namespace, name)

        if action == "get_status":
            return get_status(namespace, name)

        if action == "get_service_target_port":
            return get_service_target_port(namespace, name)

        if action == "get_readiness_probe_path":
            return get_readiness_probe_path(namespace, name)

        if action == "get_pods_using_secret":
            return get_pods_using_secret(name)

        if action == "get_persistent_volume_mount_path":
            return get_persistent_volume_mount_path(namespace, name)

        if action == "get_env_variable":
            return get_env_variable(namespace, name, "CHART_CACHE_DRIVER")

        if action == "get_database_name":
            return get_database_name(name, namespace)


        if action == "list" and resource == "events":
                logging.info("Fetching events.")
                return get_kubectl_events(namespace)

        if action == "config_view" :
                logging.info("Fetching kubeconfig contexts.")

                contexts, active_context = config.list_kube_config_contexts()
                logging.info("Successfully fetched kubeconfig contexts.")
        
                config_view = {
                 "contexts": [context["name"] for context in contexts],
                 "active_context": active_context["name"]
                }
                return config_view

        if action == "can_create_namespace":
            # Check if the namespace already exists
            logging.info(f"Checking if namespace '{name}' can be created.")
            existing_namespaces = [item.metadata.name for item in v1.list_namespace().items]
            if name in existing_namespaces:
                return "No we cannot create a namespace with this name as it already exists"
            logging.info(f"Namespace '{name}' can be created.")
            return "Yes ,It is possible to create"

        
        if action == "list" and resource == "contexts":
            contexts, active_context = config.list_kube_config_contexts()
            logging.info("Successfully fetched kubeconfig contexts.")
        
            active_configs = {
                 "active_context": active_context["name"]
            }
            return active_configs

        if action == "version":
            logging.info("Fetching Kubernetes version.")
            return client.VersionApi().get_code()

        if resource == "nodes":
                logging.info("Fetching nodes and sorting by allocatable CPU.")
                response = v1.list_node()
                items = response.items
                # Extract and sort nodes based on allocatable CPU, descending
                sorted_nodes = sorted(
                    items,
                    key=lambda node: int(node.status.allocatable["cpu"].replace("m", "")),
                    reverse=True
                )
                # Return the top nodes (e.g., top 3), the value can be accessed dynamically
                return [{"name": node.metadata.name, "cpu_allocatable": node.status.allocatable["cpu"]} for node in sorted_nodes[:10]]

        if resource == "namespaces":     
                logging.info("Listing namespaces.")
                response = v1.list_namespace()
                return [item.metadata.name for item in response.items] 
            
        # Action: List resources
        if action == "list":
            resource_map = {
                "pods": v1.list_namespaced_pod,
                "services": v1.list_namespaced_service,
                "configmaps": v1.list_namespaced_config_map,
                "secrets": v1.list_namespaced_secret,
                "deployments": apps_v1.list_namespaced_deployment,
                "replicasets": apps_v1.list_namespaced_replica_set,
                "statefulsets": apps_v1.list_namespaced_stateful_set,
                "persistentvolumes": v1.list_persistent_volume,
                "persistentvolumeclaims": v1.list_namespaced_persistent_volume_claim,
                "events": v1.list_event_for_all_namespaces,
                "namespaces": v1.list_namespace,
                "nodes": v1.list_node
            }

           
                
            if resource not in resource_map:
                logging.error(f"Unsupported resource: {resource}")
                return f"Unsupported resource: {resource}"

            response = resource_map[resource]() if resource in ["events", "persistentvolumes"] else resource_map[resource](namespace=namespace)
            items = response.items
            logging.info(f"Fetched {len(items)} items for resource '{resource}'.")


            if output_format == "wide":
                return [{"name": item.metadata.name, "status": getattr(item.status, "phase", "Unknown")} for item in items]
            elif output_format == "json":
                return [item.to_dict() for item in items]
            elif output_format == "yaml":
                return [item.to_dict() for item in items]
            elif output_format and "custom-columns" in output_format:
                columns = output_format.split("=")[-1].split(",")
                return [
                    {col.split(":")[0]: eval(".".join(["item"] + col.split(":")[1:])) for col in columns}
                    for item in items
                ]
            else:
                return [clean_resource_name(item.metadata.name) for item in items]

        # Action: Count resources
        elif action == "count":
            resource_list = handle_kubernetes_action("list", resource, namespace)
            count = len(resource_list);                                         
            logging.info(f"Counted {count} items for resource '{resource}' in namespace '{namespace}'.")
            return count


        # Action: Describe resources
        elif action == "describe":
            if resource == "pods":
                pod = v1.read_namespaced_pod(name=name, namespace=namespace)
                return pod.to_dict()
            elif resource == "services" and name:
                if namespace:
                # If namespace is provided, fetch service details directly
                  service = v1.read_namespaced_service(name=name, namespace=namespace)
                else:
                  # If namespace is not provided, search across all namespaces
                 services = v1.list_service_for_all_namespaces()
                 service = next((svc for svc in services.items if svc.metadata.name == name), None)
                 if not service:
                   return f"Service '{name}' not found in any namespace."

       
                if output_format == "namespace":
                   return {"namespace": service.metadata.namespace}
        
                # Default: Return the full service details
                return service.to_dict()
            elif resource == "configmaps":
                configmap = v1.read_namespaced_config_map(name=name, namespace=namespace)
                return configmap.to_dict()
            elif resource == "secrets":
                secret = v1.read_namespaced_secret(name=name, namespace=namespace)
                return secret.to_dict()
            elif resource == "deployments":
                deployment = apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
                return deployment.to_dict()
            elif resource == "events":
                events = v1.list_namespaced_event(namespace=namespace)
                return [event.to_dict() for event in events.items]
            elif resource == "nodes":
                nodes = v1.list_node()  
                return [node.to_dict() for node in nodes.items]  
      
            else:
                return f"Describe not supported for resource: {resource}"

        # Action: Get status
        elif action == "status":
            logging.info(f"Describing status")
            if resource == "pods":
                status = v1.read_namespaced_pod_status(name=name, namespace=namespace).status.phase
            elif resource == "deployments":
                status = apps_v1.read_namespaced_deployment_status(name=name, namespace=namespace).status.ready_replicas
            else:
                return f"Status fetching not supported for resource: {resource}"
            return f"Status of {resource} '{name}': {status}"

        # Action: Logs
        elif action == "logs":
            logging.info(f"Fetching logs for pod '{name}' in namespace '{namespace}'.")
            if name:
                if watch_mode:
                    w = watch.Watch()
                    log_stream = w.stream(v1.read_namespaced_pod_log, name=name, namespace=namespace)
                    return [line for line in log_stream]
                else:
                    logs = v1.read_namespaced_pod_log(name=name, namespace=namespace)
                    return logs
            else:
                logging.error("Logs action requires a specific pod name.")
                return "Logs action requires a specific pod name."

        # Action: Watch resources
        elif action == "watch":
            w = watch.Watch()
            watch_stream = w.stream(v1.list_namespaced_pod, namespace=namespace)
            return [event for event in watch_stream]
        else:
           logging.error(f"Unsupported action: {action}")
           return "Unsupported action or missing parameters."
    except client.exceptions.ApiException as e:
        logging.error(f"Kubernetes API exception: {e}")
        return f"Kubernetes API exception: {e.reason}"
    except Exception as e:
        logging.error(f"Unhandled exception: {e}")
        return f"Unhandled exception: {str(e)}"


def correct_resource(resource: str) -> str:
    """Correct spelling mistakes in resource names."""
    logging.info(f"Correcting resource: {resource}")
    return difflib.get_close_matches(resource, SUPPORTED_RESOURCES, n=1, cutoff=0.6)[0] if resource else "unsupported"

def correct_action(action: str) -> str:
    """Correct spelling mistakes in action names using fuzzy matching."""
    logging.info(f"Correcting action: {action}")
    return difflib.get_close_matches(action, SUPPORTED_ACTIONS, n=1, cutoff=0.6)[0] if action else "unsupported"

def extract_service_name_from_query(query: str) -> str:
    """
    Extract the service name from a query string.
    """
    words = query.lower().split()
    # Check for the word "service" and return the word following it
    if "service" in words:
        service_index = words.index("service")
        if service_index + 1 < len(words):
            return words[service_index + 1]  # Return the word after "service"
    return None  # Return None if no service name is found

def extract_database_query_type(query: str) -> dict:
    """Extract database-related query information."""
    database_patterns = {
        'name': r'(what|which|get).*(database|db)(\s+name|\s+being used|\s+using)',
        'connection': r'(database|db).*(connection|url|string)',
        'credentials': r'(database|db).*(credentials|password|user)',
    }
    
    for query_type, pattern in database_patterns.items():
        if re.search(pattern, query.lower()):
            return {
                'type': query_type,
                'component': extract_component_name(query)
            }
    return None

def extract_component_name(query: str) -> str:
    """Extract Harbor component name from query."""
    harbor_components = [
        "harbor-core", "harbor-registry", "harbor-portal", "harbor-db", 
        "harbor-database", "harbor-redis", "harbor-jobservice", "harbor-trivy",
        "postgresql"
    ]
    
    for component in harbor_components:
        if component.lower() in query.lower():
            return component
    return None

def extract_pod_count_query(query: str) -> bool:
    """Detect various forms of pod count queries."""
    pod_count_patterns = [
        r'how many pods?( are there)? in the cluster',
        r'number of pods?( in|across)( the)? cluster',
        r'total (number of )?pods?( in| across)?( the)? cluster',
        r'count( of| all| the)? pods?( in| across)?( the)? cluster',
        r'list( all)? pods? count( in| across)?( the)? cluster',
        r'get( all)? pods? count( in| across)?( the)? cluster',
        r'show( me)?( all)? pods?( count)?( in| across)?( the)? cluster',
        r'pods? count( in| across)?( the)? cluster',
        r'how many pods? (do we have|are running|exist)',
        r'cluster pods? count',
        r'current pods? count',
        r'active pods?( in| across)?( the)? cluster'
    ]
    
    return any(re.search(pattern, query.lower()) for pattern in pod_count_patterns)


def process_query_with_gpt(query: str) -> dict:
    """
    Use GPT-4 to determine the action, resource type, namespace, and optional target name.
    """
    try:
        logging.info(f"Received query: {query}")

        if extract_pod_count_query(query):
            logging.info("Detected cluster-wide pod count query")
            return {
                "action": "count",
                "resource": "pods",
                "namespace": None,  # None indicates all namespaces
                "name": None,
                "file_path": None,
                "output_format": None,
                "watch_mode": False,
                "query_params": {
                    "all_namespaces": True
                }
            }
         # Dynamic Namespace Lookup
        # def find_harbor_namespace():
        #     from kubernetes import client, config
        #     config.load_kube_config()
        #     v1 = client.CoreV1Api()
        #     services = v1.list_service_for_all_namespaces()
        #     for svc in services.items:
        #         if "harbor" in svc.metadata.name:
        #             return svc.metadata.namespace
        #     return None

        # # Default Namespace Handling
        # default_namespace = find_harbor_namespace() or "default"

        # db_query = extract_database_query_type(query)
        # if db_query:
        #     # Get the namespace first
        #     all_namespaces = handle_kubernetes_action("list", "namespaces")
        #     target_namespace = None
        #     for ns in all_namespaces:
        #         if "harbor" in ns.lower():
        #             target_namespace = ns
        #             break
            
        #     return {
        #         "action": "get_database_info",
        #         "resource": "secrets",
        #         "namespace": target_namespace or "default",
        #         "name": None,  # Will be determined by the handler
        #         "file_path": None,
        #         "output_format": None,
        #         "watch_mode": False,
        #         "query_params": {
        #             "query_type": db_query['type'],
        #             "component": db_query['component'],
        #             "info_type": "database_name"
        #         }
        #     }

        database_patterns = [
            r"(what|which|get|find).*(database|db).*name",
            r"database.*(using|used|configured)",
            r"postgresql.*(database|db)",
            r"name.*database.*postgresql"
        ]

        if any(re.search(pattern, query.lower()) for pattern in database_patterns):
            logging.info("Detected database name query")
            component = extract_component_name(query)
            
            return {
                "action": "get_database_info",
                "resource": "secrets",
                "namespace": "default",  # Will be determined by the handler
                "name": component if component else "harbor-database",
                "file_path": None,
                "output_format": None,
                "watch_mode": False,
                "query_params": {
                    "component": component,
                    "info_type": "database_name",
                    "search_terms": ["POSTGRES_DB", "DB_NAME", "DATABASE_NAME"]
                }
            }

        
        if "namespace" in query.lower() and "service" in query.lower():
          if "harbor" in query.lower():
            return {
            "action": "describe",
            "resource": "services",
            "namespace": None,  # Search across all namespaces
            "name": "harbor",   # Use partial match for "harbor"
            "output_format": "namespace"
            }
          else:
        # Dynamically extract service name from the query
           service_name = extract_service_name_from_query(query)
           if service_name:
            return {
                "action": "describe",
                "resource": "services",
                "namespace": None,  # Search across all namespaces
                "name": service_name,  # Use the extracted service name
                "output_format": "namespace"
            }
           else:
            return {
                "error": "Service name not found in query. Please specify a valid service name."
            }

            

        # if "total pods" in query.lower() or "count pods" in query.lower():
        #     return {
        #         "action": "count_pods",
        #         "resource": "pods",
        #         "namespace": None,
        #         "name": None,
        #         "file_path": None,
        #         "output_format": None,
        #         "watch_mode": False,
        #     }

        if "container port" in query.lower() and "harbor-core" in query.lower():
            return {
                "action": "get_container_port",
                "resource": "deployments",
                "namespace": "harbor",
                "name": "harbor-core",
                "file_path": None,
                "output_format": None,
                "watch_mode": False,
            }

        if "status of harbor registry" in query.lower():
            return {
                "action": "get_status",
                "resource": "deployments",
                "namespace": "harbor",
                "name": "harbor-registry",
                "file_path": None,
                "output_format": None,
                "watch_mode": False,
            }

        if "redis svc" in query.lower() and "route traffic to" in query.lower():
            return {
                "action": "get_service_target_port",
                "resource": "services",
                "namespace": "harbor",
                "name": "harbor-redis",
                "file_path": None,
                "output_format": None,
                "watch_mode": False,
            }

        if "readiness probe path" in query.lower() and "harbor core" in query.lower():
           return {
              "action": "get_readiness_probe_path",
              "resource": "deployments",
              "namespace": "harbor",
              "name": "harbor-core",
              "file_path": None,
              "output_format": None,
              "watch_mode": False,
           }

        if "pod" in query.lower() and "secret" in query.lower():
      
           
                  # Enhanced regex to handle varied phrasing
              match = re.search(r"with the (.*?) secret", query.lower())
              if match:
                secret_name = match.group(1).strip()  # Strip extra whitespace
              else:
    # Fallback to check for "secret" keyword and nearby words
                words = query.lower().split()
                if "secret" in words:
                  idx = words.index("secret")
                  if idx > 0:  # Ensure there's a word before "secret"
                   secret_name = words[idx - 1]
                else:
                   secret_name = None

              if not secret_name:
                 logging.error(f"Unable to extract secret name from query: {query}")
                 return {
                    "error": "Secret name could not be extracted from the query. Please check the query format."
                 }

              logging.info(f"Extracted secret name: {secret_name}")
              return {
                    "action": "get_pods_using_secret",
                    "resource": "pods",
                    "namespace": None,
                    "name": secret_name,  # Use the extracted secret name
                    "file_path": None,
                    "output_format": None,
                    "watch_mode": False,
                    }


        if "mount path" in query.lower() and "harbor database" in query.lower():
            return {
                "action": "get_persistent_volume_mount_path",
                "resource": "deployments",
                "namespace": "harbor",
                "name": "harbor-database",
                "file_path": None,
                "output_format": None,
                "watch_mode": False,
            }

        if "environment variable" in query.lower() and "chart_cache_driver" in query.lower():
            return {
                "action": "get_env_variable",
                "resource": "pods",
                "namespace": "harbor",
                "name": "harbor-core",
                "file_path": None,
                "output_format": None,
                "watch_mode": False,
            }

        # if "name of the database" in query.lower() and ("harbor" in query.lower() or "postgresql" in query.lower()):
        #    logging.info("Processing query to get the database name.")
        #    return {
        #         "action": "get_database_name",
        #         "resource": "secrets",
        #         "namespace": "harbor",  # Assuming Harbor is deployed in the 'harbor' namespace
        #         "name": "harbor-database-secret",  # The name of the secret containing DB connection details
        #         "file_path": None,
        #         "output_format": None,
        #         "watch_mode": False,
        #    }


        if "config view" in query.lower() or "view config" in query.lower():
            logging.info("Processing 'config view' query")
            return {
                    "action": "config_view",
                    "resource": "config_view",
                    "namespace": None,
                    "name": None,
                    "file_path": None,
                    "output_format": None,
                    "watch_mode": False,
                }
        if "version" in query.lower():
            logging.info("Processing 'version' query")
            return {
                "action": "version",
                "resource": "nodes",
                "namespace": None,
                "name": None,
                "file_path": None,
                "output_format": None,
                "watch_mode": False,
            }   
        system_prompt = """
        You are a Kubernetes AI assistant. Extract the following details from the user's query:
        - 'action': one of (list, count, status, delete, apply, describe, logs, watch)
        - 'resource': one of (pods, services, configmaps, secrets, deployments, replicasets, statefulsets, nodes, persistentvolumes, persistentvolumeclaims, events, namespaces, logs)
        - 'namespace': default if unspecified
        - 'name': optional for specific resources
        Ensure your response is a valid JSON object with keys: action, resource, namespace, name, file_path, output_format, watch_mode.
        """

        # GPT-4 API call
        logging.info("Calling GPT-4 API...")
        response = openai.ChatCompletion.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": query}
            ]
        )

        # Log the full response
        logging.info(f"Full GPT-4 API response: {response}")

        # Validate and parse response content
        if not response or "choices" not in response or not response["choices"]:
            logging.error("GPT-4 API returned an empty or malformed response.")
            raise ValueError("GPT-4 API returned an empty or malformed response.")

        response_content = response["choices"][0]["message"]["content"].strip()
        logging.info(f"GPT-4 response content: {response_content}")

        # Attempt to parse the response as JSON
        try:
            gpt_response = json.loads(response_content)
            logging.info(f"Parsed GPT-4 response: {gpt_response}")                       
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing GPT-4 response: {e}")
            return {"error": "Failed to process GPT-4 response. Response was not valid JSON."}

        # Correct any typos in action and resource
        gpt_response["action"] = correct_action(gpt_response.get("action", ""))
        gpt_response["resource"] = correct_resource(gpt_response.get("resource", ""))

        # Validate extracted fields
        if gpt_response["resource"] == "unsupported":
            logging.error("Unsupported resource specified in the query.")
            return {"error": "Unsupported resource specified in the query."}
        if gpt_response["action"] == "unsupported":
            logging.error("Unsupported action specified in the query.")
            return {"error": "Unsupported action specified in the query."}
        if gpt_response["action"] == "apply":
                # No additional parameters are needed for checking if namespace can be created
                return {
                    "action": "can_create_namespace",
                    "resource": gpt_response.get("resource"),
                    "namespace": gpt_response.get("namespace", "default"),
                    "name": gpt_response.get("name"),
                    "file_path": None,
                    "output_format": None,
                    "watch_mode": False,
                       }
        if gpt_response["action"] == "config_view":
                # No additional parameters are needed for config_view
                return {
                    "action": "config_view",
                    "resource": "config_view",
                    "namespace": gpt_response.get("namespace", "default"),
                    "name": None,
                    "file_path": None,
                    "output_format": None,
                    "watch_mode": False,
                      }    
        # Add defaults for namespace and output_format if not present
        gpt_response.setdefault("namespace", "default")
        gpt_response.setdefault("output_format", None)
        gpt_response.setdefault("watch_mode", False)
        logging.info(f"Final response: {gpt_response}")
        return gpt_response
    except openai.error.AuthenticationError:
        logging.error("Authentication failed. Check your OpenAI API key.")
        return {"error": "Authentication error with GPT-4 API."}
    except openai.error.RateLimitError:
        logging.error("Rate limit exceeded for GPT-4 API.")
        return {"error": "Rate limit exceeded. Try again later."}
    except ValueError as e:
        logging.error(f"ValueError: {e}")
        return {"error": str(e)}
    except Exception as e:
        logging.error(f"Error processing query with GPT-4: {e}")
        return {"error": f"Error processing query with GPT-4: {e}"}

def format_answer(data) -> str:
    """Format different types of data into a string answer."""
    if isinstance(data, dict):
        if "total_pods" in data:
            return str(data["total_pods"])
        elif "pods_by_namespace" in data:
            return f"Total pods: {data['total_pods']}"
        elif "mount_path" in data:
            return f"Mount path: {data['mount_path']}"
        elif "error" in data:
            return f"Error: {data['error']}"
        else:
            return json.dumps(data, indent=2)
    elif isinstance(data, (list, tuple)):
        return json.dumps(data, indent=2)
    else:
        return str(data)

@app.route('/query', methods=['POST'])
def handle_query():
    """
    Handle incoming Kubernetes queries and respond with appropriate information.
    """
    try:
        logging.info("Received POST request at /query endpoint.")
        request_data = request.json
        query = request_data.get('query')
        if not query:
            logging.error("Query is missing in the request.")
            return jsonify({"error": "Query is missing in the request."}), 400

        # Process the query using GPT-4
        logging.info(f"Processing query: {query}")
        gpt_response = process_query_with_gpt(query)
        if "error" in gpt_response:
            logging.error(f"GPT-4 processing error: {gpt_response['error']}")
            return jsonify({"error": gpt_response["error"]}), 400

        # Extract action parameters
        action = gpt_response["action"]
        resource = gpt_response["resource"]
        namespace = gpt_response.get("namespace", "default")
        name = gpt_response.get("name")
        file_path = gpt_response.get("file_path")
        output_format = gpt_response.get("output_format", None)
        watch_mode = gpt_response.get("watch_mode", False)
        query_params = gpt_response.get("query_params", {})

        logging.info(f"Action: {action}, Resource: {resource}, Namespace: {namespace}, Name: {name}, FilePath: {file_path}, OutputFormat: {output_format}, WatchMode: {watch_mode}")
        kube_data = handle_kubernetes_action(
            action,
            resource,
            namespace,
            name,
            file_path,
            output_format,
            watch_mode,
            query_params
        )
       # Format the answer based on the type of response
        formatted_answer = format_answer(kube_data)

        # Create and validate response using Pydantic model
        try:
            response = QueryResponse(
                query=query,
                answer=formatted_answer
            )
            
            logging.info(f"Response: {response.dict()}")
            return jsonify(response.dict()), 200
        except Exception as e:
            logging.error(f"Error creating response model: {e}")
            return jsonify({"error": f"Error formatting response: {str(e)}"}), 500
       
    except ValidationError as ve:
        # Handle Pydantic validation errors
        logging.error(f"Pydantic validation error: {ve}")
        return jsonify({"error": "Validation error", "details": ve.errors()}), 400
    except Exception as e:
        logging.error(f"Unhandled exception: {str(e)}")
        return jsonify({"error": f"An internal error occurred: {str(e)}"}), 500
if __name__ == "__main__":
        logging.info("Starting Flask application.")
        app.run(host="0.0.0.0", port=8000)    
