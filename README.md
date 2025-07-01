## Using scanner-pubsub
- Build the docker image using the given Dockerfile and upload it to `Artifact Registry`.
- Create a Cloud Run Job using the above docker image, and add the following env. variables:
  - GCS_BUCKET (bucket name where domains file is stored)
  - DOMAIN_FILE (name of the domains file)
  - PUBSUB_TOPIC (name of the pubsub topic)
  - GCP_PROJECT (name of the GCP project)
- Execute the Cloud Run Job to publish domains to the PubSub queue.


## Using subdomain-finder, puredns-finder and naabu-scanner
- Build the docker image using the given Dockerfile and upload it to `Artifact Registry`.
- Update the `image` path in GKE deployment file to use the above docker image.
- Modify other env. variables as needed.
