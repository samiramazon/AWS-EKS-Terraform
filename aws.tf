 provider "aws" {
	region = "ap-south-1"
	shared_credentials_file = file("C:/Users/Abuzar/.aws/credentials")
	profile = "terraform"
	}