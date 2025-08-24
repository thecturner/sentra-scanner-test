# S3 Test Buckets Terraform Deployment

This Terraform project creates 3 globally unique S3 buckets with realistic test files to simulate email scanning scenarios.

## Bucket Names

- test-bucket-1-ct-us-east1-20250822
- test-bucket-2-ct-us-east1-20250822
- test-bucket-3-ct-us-east1-20250822

Each bucket will receive one zip file with 4 files inside:
- Some files contain 1 email
- Some contain multiple emails
- Some contain no email addresses

## How to Use

1. Download the 3 zip files:
   - `test-bucket-1-ct-us-east1-20250822.zip`
   - `test-bucket-2-ct-us-east1-20250822.zip`
   - `test-bucket-3-ct-us-east1-20250822.zip`

2. Place them in the same directory as `main.tf`.

3. Run the following Terraform commands:

```bash
terraform init
terraform apply
```

4. This will:
   - Create the 3 S3 buckets
   - Upload each zip file into the corresponding bucket

You can now run your email-scanning deployment against these test buckets.
