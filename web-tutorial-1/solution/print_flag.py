import functions_framework
import base64
import json
import logging
import os
from google.cloud import pubsub_v1  # Import the Pub/Sub client library

# Initialize logging
logging.basicConfig(level=logging.INFO)

# Google Cloud Project ID
PROJECT_ID = "project-id"  # Set your project ID here
PUBSUB_TOPIC = "flag" #set your topic

@functions_framework.http
def printFlag(request):
    """
    Cloud Function that fetches a flag from Pub/Sub when it receives a GET request.
    Args:
        request (flask.Request): The request object.
        <https://flask.palletsprojects.com/en/1.1.x/api/#incoming-request-data>
    Returns:
        The HTTP response.
    """
    if request.method == 'GET':
        logging.info("Received a GET request")

        # Initialize Pub/Sub subscriber client
        subscriber = pubsub_v1.SubscriberClient()
        topic_path = subscriber.topic_path(PROJECT_ID, PUBSUB_TOPIC)
        subscription_name = "flag-sub"  # Choose a unique subscription name
        subscription_path = subscriber.subscription_path(PROJECT_ID, subscription_name)
        subscriber.get_subscription(request={"subscription": subscription_path})
  
        try:
            # Pull the most recent message
            response = subscriber.pull(
                request={"subscription": subscription_path, "max_messages": 1}
            )

            if response.received_messages:
                received_message = response.received_messages[0]
                msg = received_message.message
                # Decode the Pub/Sub message data
                data = msg.data.decode('utf-8')
                logging.info(f"Retrieved flag: {data}")

                # Acknowledge the message
                subscriber.acknowledge(
                    request={"subscription": subscription_path, "ack_ids": [received_message.ack_id]}
                )
                logging.info(f"Acknowledged message.")
                return data, 200 # return the data

            else:
                logging.info("No messages in the subscription.")
                return "No flag found in Pub/Sub topic.", 204  # No content

        except Exception as e:
            logging.error(f"Error pulling/acknowledging message: {e}", exc_info=True)
            return f"Error: {e}", 500
        finally:
             subscriber.close()

    else:
        logging.warning(f"Incorrect HTTP method: {request.method}")
        return "Only GET requests are accepted", 405
        return "Error: 'myparam' URL parameter not found.", 400