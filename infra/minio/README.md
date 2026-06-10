# MinIO

Placeholder for bucket and object storage configuration.



## Local Browser Multipart Upload CORS

RAMSight direct evidence multipart upload uses backend-generated presigned URLs, then the browser uploads parts directly to MinIO/S3. For local development, configure CORS on the evidence bucket so the frontend can `PUT` parts and read the `ETag` response header.

The development CORS policy is stored in `infra/minio/cors.json`. Apply it with an `mc` client configured for the local MinIO service, for example:

```bash
mc alias set ramsight-local http://localhost:9000 change-me change-me
mc cors set infra/minio/cors.json ramsight-local/evidence
mc cors info ramsight-local/evidence
```

Use the real local MinIO credentials if you changed `MINIO_ACCESS_KEY` or `MINIO_SECRET_KEY`. Do not expose MinIO credentials in the frontend; RAMSight only sends short-lived presigned URLs to the browser.
