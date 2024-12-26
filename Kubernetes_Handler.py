from kubernetes import client, config, watch
import logging
import re
import difflib
import subprocess 

# Load Kubernetes configuration
config.load_kube_config()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",filename="agent.log", 
    filemode="a")

def clean_resource_name(name: str) -> str:
    try:
        # Split the string by '-' and dynamically extract the base name
        parts = name.split('-')
        if len(parts) > 2:  # Ensure the name has enough segments
            base_name = '-'.join(parts[:-2])  # Keep all but the last 2 segments
        else:
            base_name = name  # If too few segments, return the whole name
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
