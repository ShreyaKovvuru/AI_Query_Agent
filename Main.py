from flask import Flask, request, jsonify
from pydantic import BaseModel, ValidationError
from flask_cors import CORS
from Kubernetes_Handler import (
    clean_resource_name,
    get_kubectl_events,
    handle_kubernetes_action
)
from Gpt_Handler import correct_resource, correct_action, process_query_with_gpt
import json
import logging 


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="agent.log",
    filemode="a"
)

app = Flask(__name__)
CORS(app) 

# Define the Pydantic model for response format
class QueryResponse(BaseModel):
    query: str
    answer: str

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
