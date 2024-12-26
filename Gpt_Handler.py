import openai
import logging
import json
import difflib
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",filename="agent.log", 
    filemode="a")

# Set up OpenAI API key
openai.api_key = OPENAI_API_KEY

SUPPORTED_RESOURCES = [ "pods", "services", "configmaps", "secrets", "deployments",
    "replicasets", "statefulsets", "nodes", "persistentvolumes", "persistentvolumeclaims", "events", "namespaces","contexts"]
SUPPORTED_ACTIONS = ["list", "count", "status", "delete", "apply", "describe", "logs", "watch","config_view","version"]

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
