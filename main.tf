# configure the provider
provider "aws" {
  region = "ap-south-1"
  profile = "new_tf"
}

# creating a key pair
resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "aws_key_pair" "generated_key" {
  key_name   = "deploy-key"
  public_key = tls_private_key.key.public_key_openssh
}

# saving key to local file
resource "local_file" "deploy-key" {
    content  = tls_private_key.key.private_key_pem
    filename = "/root/terra/task2/deploy-key.pem"
    file_permission = "0400"
}

# creating a SG
resource "aws_security_group" "allow_ssh_http_nfs" {
  name        = "allow_ssh_http_nfs"
  description = "Allow ssh and http and nfs inbound traffic"
  
  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "NFS"
    from_port	= 2049
    to_port	= 2049
    protocol	= "tcp"
    cidr_blocks	= ["0.0.0.0/0"]

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_ssh_http_nfs"
  }
}


# launching an ec2 instance
resource "aws_instance" "myin" {
  ami  = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = aws_key_pair.generated_key.key_name
  security_groups = [ "allow_ssh_http_nfs" ]
  

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.key.private_key_pem
    host     = aws_instance.myin.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd  php git amazon-efs-utils nfs-utils -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
  }

  tags = {
    Name = "os1"
  }
}

# efs 
resource "aws_efs_file_system" "efs" {
  depends_on = [
    aws_instance.myin,
    aws_security_group.allow_ssh_http_nfs, ]
  creation_token = "my-product"
  
  tags = {
    Name = "MyProduct"
  }
}

# efs access point 
resource "aws_efs_access_point" "ap" {
  file_system_id = aws_efs_file_system.efs.id
  depends_on = [ aws_efs_file_system.efs, ]
}

# efs policy
resource "aws_efs_file_system_policy" "policy" {
  
  depends_on = [ aws_efs_file_system.efs, ]
  file_system_id = aws_efs_file_system.efs.id
   
  
  policy = <<POLICY
	{
	    "Version": "2012-10-17",
	    "Id": "efs-policy-wizard-37ea40d1-826a-4398-99d6-a4561182f9f6",
	    "Statement": [
	        {
	            "Sid": "efs-statement-65263caf-dba3-4299-b808-4da9635bba63",
	            "Effect": "Allow",
	            "Principal": {
	                "AWS": "*"
	            },
	            "Resource": "${aws_efs_file_system.efs.arn}",
	            "Action": [
	                "elasticfilesystem:ClientMount",
	                "elasticfilesystem:ClientWrite",
	                "elasticfilesystem:ClientRootAccess"
	            ],
	            "Condition": {
	                "Bool": {
	                    "aws:SecureTransport": "true"
	                }
	            }
	        }
	    ]
	}
	POLICY
}

# efs mount target
resource "aws_efs_mount_target" "alpha" {
  file_system_id = aws_efs_file_system.efs.id
  subnet_id = aws_instance.myin.subnet_id
  security_groups = [ aws_security_group.allow_ssh_http.id ]
  depends_on = [ aws_efs_file_system.efs, 
                 aws_efs_access_point.ap, 
                 aws_efs_file_system_policy.policy,]
}

resource "null_resource" "nullremote1"  {
  depends_on = [
    aws_efs_mount_target.alpha,
    aws_efs_file_system_policy.policy,
  ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.key.private_key_pem
    host     = aws_instance.myin.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo chmod ugo+rw /etc/fstab",
      "sudo mount ${aws_efs_file_system.efs.id}:/ /var/www/html/",
      "sudo echo '${aws_efs_file_system.efs.id}:/ /var/www/html/ efs tls,_netdev' >> /etc/fstab",
      "sudo mount -a -t efs,nfs4 defaults",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/mykg/sampleCloud.git /var/www/html/",
    ]
  }
}


################## cloud front and s3 ##################
resource "aws_s3_bucket" "b" {
  bucket = "mynkbucket19"
  acl    = "public-read"

  tags = {
    Name        = "mynkbucket"
  }
}

resource "aws_s3_bucket_object" "object" {
  depends_on = [ aws_s3_bucket.b, ]
  bucket = "mynkbucket19"
  key    = "x.jpg"
  source = "/root/terra/task2/x.jpg"
  acl = "public-read"
}


locals {
  s3_origin_id = "S3-mynkbucket19"
}

# origin access id
resource "aws_cloudfront_origin_access_identity" "oai" {
  comment = "this is OAI to be used in cloudfront"
}

# creating cloudfront 
resource "aws_cloudfront_distribution" "s3_distribution" {

  depends_on = [ aws_cloudfront_origin_access_identity.oai, 
                 null_resource.nullremote1,  
  ]

  origin {
    domain_name = aws_s3_bucket.b.bucket_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }

    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.key.private_key_pem
    host     = aws_instance.myin.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo su << EOF",
      "echo \"<img src='http://${aws_cloudfront_distribution.s3_distribution.domain_name}/${aws_s3_bucket_object.object.key}'>\" >> /var/www/html/index.html",
      "EOF"
    ]
  }


  enabled             = true
  is_ipv6_enabled     = true

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    viewer_protocol_policy = "redirect-to-https"
  }

  
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}


# IP
output "IP_of_inst" {
  value = aws_instance.myin.public_ip
}
