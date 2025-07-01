import os
import json
import concurrent.futures
from google.cloud import storage, pubsub_v1
from google.api_core import retry

BUCKET_NAME = os.getenv("GCS_BUCKET")
FILE_NAME = os.getenv("DOMAIN_FILE")
PUBSUB_TOPIC = os.getenv("PUBSUB_TOPIC")
PROJECT_ID = os.getenv("GCP_PROJECT")

if not BUCKET_NAME or not FILE_NAME or not PUBSUB_TOPIC or not PROJECT_ID:
    raise EnvironmentError("Missing one of: GCS_BUCKET, DOMAIN_FILE, PUBSUB_TOPIC, GCP_PROJECT")

publisher = pubsub_v1.PublisherClient()

def read_domains_from_gcs(bucket_name, file_name):
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(file_name)
    content = blob.download_as_text()
    return [line.strip() for line in content.splitlines() if line.strip()]

@retry.Retry(predicate=retry.if_transient_error)
def publish_one(domain):
    try:
        topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)
        future = publisher.publish(topic_path, data=domain.encode("utf-8"))
        print(f"Published {domain}: {future.result(timeout=10)}")
    except Exception as e:
        print(f"Failed to publish {domain}: {e}")

def main():
    domains = read_domains_from_gcs(BUCKET_NAME, FILE_NAME)
    print(f"Read {len(domains)} domains from GCS")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        count = 0
        for domain in domains:
            pool.submit(publish_one, domain)
            count += 1
        pool.shutdown(wait=True)
    print(f"Published {count} domains.")

if __name__ == "__main__":
    main()