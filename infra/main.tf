###############################################################
# Intentionally misconfigured Terraform — FOR DEMO / LEARNING #
# Checkov will flag every issue marked MISCONFIGURATION below  #
###############################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ── S3 Bucket ────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "data" {
  bucket = "my-aspm-demo-data-bucket"

  # MISCONFIGURATION: no tags, no lifecycle, no object lock
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"   # MISCONFIGURATION: CKV_AWS_20 — bucket publicly readable
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Disabled"    # MISCONFIGURATION: CKV_AWS_21 — versioning off
  }
}

# MISCONFIGURATION: CKV_AWS_19 — no server-side encryption configured
# resource "aws_s3_bucket_server_side_encryption_configuration" "data" { … }

# MISCONFIGURATION: CKV_AWS_18 — no access logging configured
# resource "aws_s3_bucket_logging" "data" { … }

# MISCONFIGURATION: CKV2_AWS_6 / CKV_AWS_53 — no public access block
# resource "aws_s3_bucket_public_access_block" "data" { … }


# ── Security Group ───────────────────────────────────────────────────────────

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web server security group"

  ingress {
    description = "Allow all inbound"   # MISCONFIGURATION: CKV_AWS_24 / CKV_AWS_25
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]        # MISCONFIGURATION: unrestricted ingress
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


# ── EC2 Instance ─────────────────────────────────────────────────────────────

resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.micro"

  # MISCONFIGURATION: CKV_AWS_8  — no IMDSv2 enforcement
  # MISCONFIGURATION: CKV_AWS_135 — no encrypted root volume
  # MISCONFIGURATION: CKV_AWS_126 — no detailed monitoring

  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name = "demo-web"
  }
}
