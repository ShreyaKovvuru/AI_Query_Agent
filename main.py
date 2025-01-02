from flask import Flask, request, jsonify
from pydantic import BaseModel, ValidationError
from flask_cors import CORS
from kubernetes import client, config, watch
import logging
import re
import difflib
import subprocess 
import openai
import json
import os



# Load Kubernetes configuration
try:
    config.load_kube_config()
except Exception as e:
    logging.error(f"Failed to load kubeconfig: {e}")

# Set the OpenAI API key from the environment variable
openai.api_key = os.environ["OPENAI_API_KEY"]


# Check if the API key is not set
if not openai.api_key:
    logging.error("OPENAI_API_KEY environment variable is not set.")
    raise EnvironmentError("The OPENAI_API_KEY environment variable is required but not set.")


SUPPORTED_RESOURCES = [ "pods", "services", "configmaps", "secrets", "deployments",
    "replicasets", "statefulsets", "nodes", "persistentvolumes", "persistentvolumeclaims", "events", "namespaces","contexts"]
SUPPORTED_ACTIONS = ["list", "count", "status", "delete", "apply", "describe", "logs", "watch","config_view","version"]



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="agent.log",
    filemode="a"
)

app = Flask(__name__)
# CORS(app)


# Define the Pydantic model for response format
class QueryResponse(BaseModel):
    query: str
    answer: str


def clean_resource_name(name: str) -> str:
    try:
        # Use regex to extract the meaningful base name
        match = re.match(r'^([a-zA-Z]+(?:-[a-zA-Z]+)*)', name)
        if match:
            base_name = match.group(0)  # Extract the meaningful part
        else:
            base_name = name  # Fallback if no match is found
        logging.info(f"Cleaned resource name: {base_name}")
        return base_name
    except Exception as e:
        logging.error(f"Error in cleaning resource name '{name}': {e}")
        return name  # Fallback to the original name if an error occurs


def get_kubectl_events(namespace=None):
    try:
        # Build the kubectl command
        if namespace:
            command = ["kubectl", "get", "events", "-n", namespace, "-o", "wide"]
        else:
            command = ["kubectl", "get", "events", "--all-namespaces", "-o", "wide"]

        # Execute the command and capture output
        logging.info("Executing: %s", " ".join(command))
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

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

def handle_kubernetes_action(action: str, resource: str = None, namespace: str = "default", name: str = None, file_path: str = None, output_format: str = None, watch_mode: bool = False) -> str:
    logging.info(f"Handling Kubernetes action: action={action}, resource={resource}, namespace={namespace}, name={name}, file_path={file_path}, output_format={output_format}, watch_mode={watch_mode}")

    try:
        # Initialize API clients
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()

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
            elif resource == "services":
                service = v1.read_namespaced_service(name=name, namespace=namespace)
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

def process_query_with_gpt(query: str) -> dict:
    """
    Use GPT-4 to determine the action, resource type, namespace, and optional target name.
    """
    try:
        logging.info(f"Received query: {query}")
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


def beautify_json(json_input):
    try:
        
        # If input is a dictionary, no need to parse it
        if isinstance(json_input, dict):
            json_data = json_input
        else:
            # Parse the JSON string to a Python dictionary
            json_data = json.loads(json_input)
        
        # Convert the dictionary back to a formatted JSON string
        pretty_json = json.dumps(json_data, indent=4)
        return pretty_json
    except (json.JSONDecodeError, TypeError) as e:
        logging.error(f"Error beautifying JSON: {str(e)}")
        return json_input  # Return the original input if an error occurs


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

        logging.info(f"Action: {action}, Resource: {resource}, Namespace: {namespace}, Name: {name}, FilePath: {file_path}, OutputFormat: {output_format}, WatchMode: {watch_mode}")


        # Call the Kubernetes handler function using positional arguments
        kube_data = handle_kubernetes_action(
            action,
            resource,
            namespace,
            name,
            file_path,
            output_format,
            watch_mode
        )

        if not isinstance(kube_data, str):
            kube_data = json.dumps(kube_data, default=str)

        try:
            parsed_answer = json.loads(kube_data)
        except json.JSONDecodeError as e:
            
          if isinstance(kube_data, str):
            kube_data = str(kube_data)
            
            response = {
              "query": query,
              "answer": kube_data  # Use the parsed JSON object
            }
            logging.info(f"Response: {response}")  
            return response, 200
          else:    
            return jsonify({"error": "Failed to parse answer as JSON.", "details": str(e)}), 500
        
        response = {
            "query": query,
            "answer": parsed_answer  # Use the parsed JSON object
        }
        
        
        logging.info(f"Response: {response}")
        return jsonify(response), 200
       
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
