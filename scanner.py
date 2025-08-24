import boto3
import re
import json

s3 = boto3.client('s3')

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

def list_all_buckets():
    return [bucket['Name'] for bucket in s3.list_buckets()['Buckets']]

def list_objects(bucket_name):
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get('Contents', []):
            yield obj['Key']

def read_object(bucket, key):
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        return obj['Body'].read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Error reading {bucket}/{key}: {e}")
        return ""

def extract_emails(text):
    return list(set(EMAIL_REGEX.findall(text)))

def scan_bucket(bucket):
    findings = {}
    for key in list_objects(bucket):
        content = read_object(bucket, key)
        emails = extract_emails(content)
        if emails:
            findings[key] = emails
    return findings

def scan_all():
    result = {}
    for bucket in list_all_buckets():
        print(f"Scanning bucket: {bucket}")
        result[bucket] = scan_bucket(bucket)
    return result

def save_results_to_s3(results, bucket, key):
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(results, indent=2),
        ContentType='application/json'
    )

if __name__ == '__main__':
    results = scan_all()
    save_results_to_s3(results, 'sentra-results-bucket', 'scan_results.json')
