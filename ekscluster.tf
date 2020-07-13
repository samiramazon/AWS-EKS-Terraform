# Variables

variable "vpc_cidr" {
    description = "CIDR for the whole VPC"
    default = "10.0.0.0/16"
}

# VPC Creation

resource "aws_vpc" "eksvpc" {
    cidr_block = "${var.vpc_cidr}"
    enable_dns_hostnames = true
	instance_tenancy = "default"
    tags = {
        Name = "eksvpc"
    }
}

# Subnets creation 

resource "aws_subnet" "subA" {
    vpc_id = "${aws_vpc.eksvpc.id}"

    cidr_block = "10.0.1.0/24"
    availability_zone = "ap-south-1a"
	map_public_ip_on_launch=true
    tags = {
        Name = "Subnet1"
    }
}

resource "aws_subnet" "subB" {
    vpc_id = "${aws_vpc.eksvpc.id}"

    cidr_block = "10.0.2.0/24"
    availability_zone = "ap-south-1b"
	map_public_ip_on_launch=true
    tags = {
        Name = "Subnet2"
    }
}

resource "aws_subnet" "subC" {
    vpc_id = "${aws_vpc.eksvpc.id}"
	map_public_ip_on_launch=true
    cidr_block = "10.0.3.0/24"
    availability_zone = "ap-south-1c"

    tags = {
        Name = "Subnet3"
    }
}

#Internet Gateway Creation

resource "aws_internet_gateway" "eksig" {
    vpc_id = "${aws_vpc.eksvpc.id}"
	tags = {
	Name = "eksig"
	}
}

# Route Table

resource "aws_route_table" "ap-south-1a-public" {
    vpc_id = "${aws_vpc.eksvpc.id}"

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = "${aws_internet_gateway.eksig.id}"
    }

    tags = {
        Name = "Route"
    }
}

# Subnet Association

resource "aws_route_table_association" "a" {
    subnet_id = "${aws_subnet.subA.id}"
    route_table_id = "${aws_route_table.ap-south-1a-public.id}"
}

resource "aws_route_table_association" "b" {
    subnet_id = "${aws_subnet.subB.id}"
    route_table_id = "${aws_route_table.ap-south-1a-public.id}"
}
resource "aws_route_table_association" "c" {
    subnet_id = "${aws_subnet.subC.id}"
    route_table_id = "${aws_route_table.ap-south-1a-public.id}"
}

# Security Groups

resource "aws_security_group" "eks-mgmt" {
  name		  = "eks-mgmt"
  description = "Cluster Management"
  vpc_id      = "${aws_vpc.eksvpc.id}"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "wrksg1" {
  name 		  = "secgrp1"
  vpc_id      = "${aws_vpc.eksvpc.id}"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
cidr_blocks   = ["0.0.0.0/0"]
  }
egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "wrksg2" {
  name 		  = "secgrp2"
  vpc_id      = "${aws_vpc.eksvpc.id}"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
cidr_blocks   = ["0.0.0.0/0"]
  }
egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# SSH Key 

resource "tls_private_key" "ekskey" {
    algorithm = "RSA"
}

module "key_pair" {

  source = "terraform-aws-modules/key-pair/aws"
  key_name   = "ekskey"
  public_key = tls_private_key.ekskey.public_key_openssh

}

resource "local_file" "privet_key" {
    content     =tls_private_key.ekskey.private_key_pem
    filename = "ekskey.pem"
}


# EFS File System
resource "aws_efs_file_system" "EFS" {
  creation_token = "my-product"

  tags = {
    Name = "Myefs-eks"
  }
}

# Mounting EFS 

resource "aws_efs_mount_target" "subA" {
  file_system_id = "${aws_efs_file_system.EFS.id}"
  subnet_id      = "${aws_subnet.subA.id}"
security_groups = ["${aws_security_group.eks-mgmt.id}"]
}

resource "aws_efs_mount_target" "subB" {
  file_system_id = "${aws_efs_file_system.EFS.id}"
  subnet_id      = "${aws_subnet.subB.id}"
  security_groups = ["${aws_security_group.eks-mgmt.id}"]
}

resource "aws_efs_mount_target" "subC" {
  file_system_id = "${aws_efs_file_system.EFS.id}"
  subnet_id      = "${aws_subnet.subC.id}"
  security_groups = ["${aws_security_group.eks-mgmt.id}"]
}

resource "aws_efs_access_point" "efseks" {
  file_system_id = "${aws_efs_file_system.EFS.id}"
}

# Cluster Role for EKS

resource "aws_iam_role" "eks_cluster" {
  name = "eks-cluster"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks_cluster.name
}

# Cluster creation

resource "aws_eks_cluster" "aws-eks" {
  name     = "aws-eks"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = ["${aws_subnet.subA.id}","${aws_subnet.subB.id}","${aws_subnet.subC.id}"]
  }

  tags = {
    Name = "aws-eks"
  }
}

resource "aws_iam_role" "eks_nodes" {
  name = "eks-node-group"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_eks_node_group" "node1" {
  cluster_name    = aws_eks_cluster.aws-eks.name
  node_group_name = "ng-1"
  instance_types	  =["t2.micro"]
    node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = ["${aws_subnet.subA.id}"]
  remote_access {
  ec2_ssh_key	  = "ekskey"
source_security_group_ids = ["${aws_security_group.wrksg1.id}"]
  }
  disk_size		  =50
  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
  ]
}


resource "aws_eks_node_group" "node2" {
  cluster_name    = aws_eks_cluster.aws-eks.name
  node_group_name = "ng-2"
  instance_types	  =["t2.micro"]
    node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = ["${aws_subnet.subB.id}"]
  remote_access {
  ec2_ssh_key	  = "ekskey"
source_security_group_ids = ["${aws_security_group.wrksg2.id}"]
  }
  disk_size		  =50
  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
  ]
}

