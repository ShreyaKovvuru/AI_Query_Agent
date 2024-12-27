# Cleric AI_Query Agent

## Overview
The Cleric AI_Query Agent is a comprehensive application that integrates a Flask-based backend, OpenAI GPT-4, Kubernetes APIs, and a React-based responsive frontend. It enables users to interact with Kubernetes clusters by sending natural language queries through an intuitive user interface. The queries are processed to determine the desired actions and resources, which are then executed on the Kubernetes cluster, and the results are returned in a structured, readable format.

---

## Features
-- Responsive Frontend: React-based UI with Axios integration for seamless query handling.
- Natural Language Query Processing:Leverages OpenAI GPT-4 for interpreting user queries and handling spelling mistakes etc.
- Kubernetes Resource Management: Handles actions like output_formatting , counting, listing, describing , checking configurations, fetching logs, fetching status, version information and watching resources .
- Error Handling and Logging: Comprehensive logging and error reporting in both backend and frontend.
- Customizable JSON Beautification:Backend capability to format JSON responses for better readability.

---

## System Architecture

### Backend
The backend is built with Flask and provides the following functionalities:

1. Query Parsing
   - Receives natural language queries via a REST API.
   - Uses OpenAI GPT-4 to extract key parameters (action, resource, namespace, etc.).

2. Action Execution
   - Maps parsed parameters to Kubernetes API calls.
   - Handles various Kubernetes resources such as pods, services, deployments, events , config_maps , nodes , namespaces, secrets , persistent volumes .
   - Includes additional utilities for:
     - Listing contexts.
     - Listing Events
     - Listing namespaces and listing of other resources
     - Getting config views
     - Getting pods/deployment status
     - Getting log information for the pods
     - Viewing configuration.
     - Checking namespace creation eligibility.
     - Fetching logs in watch mode.

3. Utilities
   - Corrects misspelled resource or action names using fuzzy matching.
   - Beautifies JSON responses for consistent formatting.
   - Logs all major events and errors to `agent.log`.

#### Key Backend Files
- `Main.py`
  - Flask server handling API endpoints.
  - Route `/query` processes POST requests containing user queries.
- `Gpt_Handler.py`
  - Interfaces with OpenAI GPT-4 for natural language processing.
  - Validates and parses responses, ensuring compatibility with Kubernetes actions.
- `Kubernetes_Handler.py`
  - Implements logic for interacting with Kubernetes clusters using client libraries.
  - Supports actions for various Kubernetes resources:

#### Detailed Action Descriptions
1. List
   - Retrieves a list of Kubernetes resources such as pods, services, configmaps, secrets, and more.
   - Supports namespace filtering and custom output formats like JSON, YAML, or wide.

2. Count
   - Counts the number of specific Kubernetes resources within a namespace.

3. Describe
   - Provides detailed information about a specific Kubernetes resource.
   - Supported for resources like pods, services, deployments, events, and more.

4. Config View
   - Fetches and displays the Kubernetes context configurations, including active contexts.

5. Namespace Check
   - Determines if a namespace can be created or already exists in the cluster.

6. Status
   - Retrieves the current status of specific resources, such as pod phases or deployment readiness.

7. Logs
   - Fetches logs from pods. Supports streaming logs in watch mode for real-time updates.

8. Watch
   - Monitors changes in Kubernetes resources in real-time.

9. Version
   - Retrieves the Kubernetes cluster version information.

10. Fetch Nodes
    - Lists nodes in the cluster and sorts them based on allocatable CPU resources.

11. Events
    - Fetches events from the cluster, either for a specific namespace or all namespaces.

---

### Frontend
The frontend is a React-based responsive web application that communicates with the Flask backend.

1. Responsive Chat UI
   - Allows users to input natural language queries.
   - Displays both user queries and responses in a chat-like interface.

2. Axios Integration
   - Sends POST requests to the `/query` endpoint of the backend.
   - Handles responses (JSON objects or plain text) and updates the chat dynamically.

3. Error Handling**
   - Provides feedback to users if the backend encounters errors.
   - Displays loading indicators while awaiting responses.

#### Key Frontend Files
- `App.js`
  - Main React component for the UI.
  - Manages state for queries, messages, and loading indicators.
  - Implements the Axios-based API call to communicate with the backend.
- `App.css`
  - Styles for the application, ensuring a clean and responsive design.

---

## Installation and Setup

### Prerequisites
- Python 3.8+
- Node.js 14+
- Kubernetes cluster with configured kubeconfig file
- OpenAI GPT-4 API key

### Backend Setup
1. Clone the repository.
2. Navigate to the backend directory.
4. Set your OpenAI API key in `OpenAI_Integration.py`.
5. Start the Flask server:
   ```bash
   python Main.py
   ```
## Installation

To install the dependencies for this project, run the following command:

```bash
pip install -r requirements.txt
```

### Frontend Setup
1. Navigate to the frontend directory.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the React application:
   ```bash
   npm start
   ```
## Installation for React Dependencies

To install the dependencies for the React part of this project, run the following commands:

1. Install React:
   ```bash
   npm install react react-dom
   ```
   ```bash
   npm install axios
   ```
---

## API Endpoints

### `/query` (POST)
Description: Processes a user query and returns the corresponding Kubernetes resource data.

Request Body:
```json
{
  "query": "Describe the status of all pods in the default namespace"
}
```

Response:
- Success:
  ```json
  {
    "query": "Describe the status of all pods in the default namespace",
    "answer": [
      {
        "name": "pod-name",
        "status": "Running"
      }
    ]
  }
  ```
- Error:
  ```json
  {
    "error": "Unsupported resource specified in the query."
  }
  ```

---

## Logging
All logs are saved in `agent.log` with detailed information about queries, responses, and errors.

---

## Future Improvements
- Add user authentication and rate limiting.

---

## Contributing
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes with detailed messages.
4. Submit a pull request.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
