
provider "aws" {
  region = "us-east-1"
}

data "template_file" "user_data" {
  template = file("${path.module}/user_data.sh.tmpl")

  vars = {
    results_bucket_name = var.results_bucket_name
  }
}

resource "aws_s3_bucket" "results" {
  bucket = var.results_bucket_name
  force_destroy = true
}

resource "aws_s3_object" "scanner_py" {
  bucket       = aws_s3_bucket.results.id
  key          = "artifacts/scanner/scanner.py"
  source       = "${path.module}/scanner_with_archive_support.py"
  etag         = filemd5("${path.module}/scanner_with_archive_support.py")
  content_type = "text/x-python"

    depends_on = [aws_s3_bucket.results]

}


resource "aws_s3_object" "scanner_script" {
  bucket = var.results_bucket_name
  key    = "scanner/scanner.py"
  source = "${path.module}/scanner_with_archive_support.py"
  etag   = filemd5("${path.module}/scanner_with_archive_support.py")

    depends_on = [aws_s3_bucket.results]

}


resource "null_resource" "scanner_file_hash" {
  triggers = {
    scanner_hash = filesha256("${path.module}/scanner_with_archive_support.py")
  }
}

resource "aws_iam_role" "ec2_role" {
  name = "scanner-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "scanner_policy" {
  name        = "scanner-policy"
  description = "Policy allowing scanner to access S3 buckets"
  policy      = file("${path.module}/scanner_policy.json")
}

resource "aws_iam_role_policy_attachment" "scanner_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.scanner_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "scanner-instance-profile"
  role = aws_iam_role.ec2_role.name
}

data "external" "my_ip" {
  program = ["bash", "${path.module}/get_my_ip.sh"]
}

resource "aws_security_group" "scanner_sg" {
  name        = "scanner-security-group"
  description = "Allow SSH access from my IP"
  vpc_id      = data.aws_vpc.default.id  # Replace with actual VPC if needed

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [data.external.my_ip.result["cidr"]]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "scanner-sg"
  }
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_key_pair" "scanner_key" {
  key_name   = "scanner-key"
  public_key = file("~/.ssh/id_ed25519.pub")
}

data "template_cloudinit_config" "scanner_userdata" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/cloud-config"
    content = <<EOF
#cloud-config
write_files:
  - path: /etc/systemd/system/scanner.service
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=Sentra Sample S3 Scanner
      After=network-online.target cloud-init.service
      Wants=network-online.target

      [Service]
      Type=simple
      User=ec2-user
      Environment=PYTHONUNBUFFERED=1
      ExecStart=/usr/bin/python3 /opt/sentra/scanner.py
      Restart=on-failure
      RestartSec=5s
      StandardOutput=append:/var/log/scanner.log
      StandardError=append:/var/log/scanner.log

      [Install]
      WantedBy=multi-user.target

packages:
  - python3
  - python3-pip
  - unzip
  - tar
  - gzip

runcmd:
  - mkdir -p /opt/sentra
  - chown ec2-user:ec2-user /opt/sentra
  - curl -fSL "https://${aws_s3_bucket.results.bucket}.s3.${var.aws_region}.amazonaws.com/${aws_s3_object.scanner_py.key}" -o /opt/sentra/scanner.py
  - chmod +x /opt/sentra/scanner.py
  - pip3 install --upgrade pip
  - pip3 install --no-cache-dir boto3
  - systemctl daemon-reload
  - systemctl enable --now scanner
EOF
  }
}


resource "aws_instance" "scanner_vm" {
  ami                    = "ami-0c02fb55956c7d316"
  instance_type          = "t3.micro"
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids = [aws_security_group.scanner_sg.id]
  key_name = aws_key_pair.scanner_key.key_name

  user_data_base64 = data.template_cloudinit_config.scanner_userdata.rendered

  tags = {
    Name = "scanner-vm"
  }

  depends_on = [null_resource.scanner_file_hash]
}

