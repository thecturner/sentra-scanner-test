#!/bin/bash
exec > /var/log/user-data.log 2>&1
set -x


# Update and install required packages
yum update -y
amazon-linux-extras enable python3.8
yum install -y python3.8 unzip tar gzip

# Ensure pip is installed
yum install -y python3-pip

# Install boto3
pip3 install boto3

# Make sure the ec2-user owns the directory
mkdir -p /home/ec2-user
chown ec2-user:ec2-user /home/ec2-user

# Write the scanner script to disk
cat > /home/ec2-user/scanner.py <<EOF
${script}
EOF

# Set permissions
chmod +x /home/ec2-user/scanner.py

# Run it in the background
nohup python3.8 /home/ec2-user/scanner.py > /var/log/scanner.log 2>&1 &
