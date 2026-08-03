terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region for the Nitro Enclave"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type (must support Nitro Enclaves)"
  type        = string
  default     = "m5a.xlarge" # Requires at least 4 vCPUs for enclave allocation
}

variable "key_name" {
  description = "Name of the SSH key pair"
  type        = string
}

# Use Amazon Linux 2023 for native Nitro Enclave support
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# Security Group allowing SSH (for setup/deployment) and internal enclave proxy traffic
resource "aws_security_group" "cgi_nitro_sg" {
  name        = "cgi-nitro-enclave-sg"
  description = "Security group for CGI Protocol Nitro Enclave host"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # In production, restrict this to your IP/VPN
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# The physical host instance
resource "aws_instance" "cgi_nitro_host" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = var.instance_type
  key_name      = var.key_name
  
  vpc_security_group_ids = [aws_security_group.cgi_nitro_sg.id]

  # CRITICAL: This is the flag that instructs AWS to allocate physical CPU/RAM isolation
  enclave_options {
    enabled = true
  }

  # Allocate sufficient storage for the AI models and Enclave images
  root_block_device {
    volume_size = 100
    volume_type = "gp3"
  }

  tags = {
    Name        = "CGI-Protocol-Nitro-Host"
    Environment = "Production"
  }

  # User data to automatically install Docker and Nitro CLI on boot
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker git
              systemctl start docker
              systemctl enable docker
              usermod -aG docker ec2-user
              usermod -aG ne ec2-user
              
              # Allocate resources for the enclave (e.g. 2 vCPUs, 4096 MB RAM)
              # Modify /etc/nitro_enclaves/allocator.yaml
              sed -i 's/cpu_count: 2/cpu_count: 2/' /etc/nitro_enclaves/allocator.yaml
              sed -i 's/memory_mib: 512/memory_mib: 4096/' /etc/nitro_enclaves/allocator.yaml
              
              systemctl start nitro-enclaves-allocator.service
              systemctl enable nitro-enclaves-allocator.service
              EOF
}

output "instance_public_ip" {
  description = "Public IP of the Nitro Host"
  value       = aws_instance.cgi_nitro_host.public_ip
}
