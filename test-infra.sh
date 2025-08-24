#If you have deployed this infrastructure and you find that there are some inconsistencies or errors
#use these commands to troubleshoot

#DO NOT RUN THIS AS A SCRIPT. They are meant to troubleshoot step by step to find out why something may not be working


# 0. See whether cloud-init already reached final
sudo cloud-init status --long

# 1. Prove the unit file exists or not
test -f /etc/systemd/system/scanner.service && echo "unit present" || echo "unit missing"
test -f /opt/sentra/scanner.py && echo "script present" || echo "script missing"

# 2. See cloud-init logs for errors around runcmd
sudo tail -n +1 /var/log/cloud-init.log /var/log/cloud-init-output.log | grep -Ei "curl|aws s3|scanner|error|denied|No such file|failed"

# 3. If AWS CLI is not present. install it so we can test S3 access quickly
sudo yum -y install awscli

# 4. Confirm the object is reachable with your instance profile
#    Replace variables with your actual values if needed
BUCKET="sentra-results-bucket-ct-us-east1-20250822"
KEY="artifacts/scanner/scanner.py"
REGION="us-east-1"

aws s3 ls "s3://${BUCKET}/${KEY}" --region "${REGION}"
aws s3 cp "s3://${BUCKET}/${KEY}" /tmp/scanner.py --region "${REGION}" && head -5 /tmp/scanner.py


# Service is installed and enabled
systemctl is-enabled scanner
# Should print "enabled"

# Check current status
systemctl status scanner --no-pager

# Show logs from the scanner process
sudo journalctl -u scanner -n 50 --no-pager

# Or directly check your scanner log
tail -n 50 /var/log/scanner.log
