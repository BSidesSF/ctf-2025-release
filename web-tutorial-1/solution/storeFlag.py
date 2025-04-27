import functions_framework
from google.cloud import pubsub_v1
import os

# Replace with your Pub/Sub topic ID
PUBSUB_TOPIC = "flag"
PROJECT_ID = "project-id"


# Initialize Pub/Sub client
publisher = pubsub_v1.PublisherClient()

@functions_framework.http
def storeFlag(request):
    """HTTP Cloud Function to store a URL parameter in Pub/Sub."""

    if not PUBSUB_TOPIC:
        return "Error: PUBSUB_TOPIC environment variable not set.", 500

    request_args = request.args
    param_value = request_args.get('flag')  # Change 'myparam' to your desired URL parameter name

    if param_value:
        topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)
        data_bytes = param_value.encode("utf-8")

        try:
            publish_future = publisher.publish(topic_path, data=data_bytes)
            publish_future.result()  # Wait for the publish to complete
            return f"Successfully published '{param_value}' to Pub/Sub topic '{PUBSUB_TOPIC}'", 200
        except Exception as e:
            return f"Error publishing message: {e}", 500
    else:
        return "Error: 'myparam' URL parameter not found.", 400