resource "aws_security_group" "ssh" {
  name = "ssh-open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "assets-bucket"
  acl    = "public-read"
}
