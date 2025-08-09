# Terraform configuration for Solution-Automater Cloud Infrastructure

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
  
  backend "s3" {
    bucket = "solution-automater-terraform-state"
    key    = "cloud-integration/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
    dynamodb_table = "terraform-state-lock"
  }
}

# Provider configurations
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Solution-Automater"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "solution-automater"
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}

# VPC and Networking
module "vpc" {
  source = "./modules/aws-networking"
  
  project_name = var.project_name
  environment  = var.environment
  vpc_cidr     = "10.0.0.0/16"
  
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  private_subnet_cidrs = ["10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_flow_logs   = true
}

# Security Groups
module "security" {
  source = "./modules/aws-security"
  
  project_name = var.project_name
  environment  = var.environment
  vpc_id       = module.vpc.vpc_id
  
  allowed_ssh_cidr_blocks = ["10.0.0.0/8"]
  allowed_https_cidr_blocks = ["0.0.0.0/0"]
}

# S3 Buckets
module "s3_storage" {
  source = "./modules/aws-s3"
  
  project_name = var.project_name
  environment  = var.environment
  
  backup_bucket_name   = "${var.project_name}-backups-${var.environment}"
  artifact_bucket_name = "${var.project_name}-artifacts-${var.environment}"
  
  enable_versioning = true
  enable_encryption = true
  
  lifecycle_rules = {
    transition_to_ia_days      = 30
    transition_to_glacier_days = 90
    expiration_days           = 365
  }
}

# RDS MySQL
module "rds" {
  source = "./modules/aws-rds"
  
  project_name = var.project_name
  environment  = var.environment
  
  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  security_group_ids  = [module.security.rds_security_group_id]
  
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.medium"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_encrypted     = true
  
  database_name = "solution_automater"
  username      = "admin"
  
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  enable_performance_insights = true
  enable_cloudwatch_logs     = ["error", "general", "slowquery"]
  
  create_read_replica = true
  multi_az           = true
}

# MongoDB on EC2
module "mongodb_cluster" {
  source = "./modules/aws-mongodb"
  
  project_name = var.project_name
  environment  = var.environment
  
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnet_ids
  security_group_ids = [module.security.mongodb_security_group_id]
  
  instance_type = "t3.large"
  cluster_size  = 3
  
  volume_size = 100
  volume_type = "gp3"
  
  enable_backup = true
  backup_schedule = "0 2 * * *"
}

# CloudWatch Monitoring
module "monitoring" {
  source = "./modules/aws-monitoring"
  
  project_name = var.project_name
  environment  = var.environment
  
  alarm_email = "alerts@solution-automater.com"
  
  enable_detailed_monitoring = true
  log_retention_days        = 30
  
  custom_metrics_namespace = "SolutionAutomater"
}

# IAM Roles and Policies
module "iam" {
  source = "./modules/aws-iam"
  
  project_name = var.project_name
  environment  = var.environment
  
  s3_bucket_arns = [
    module.s3_storage.backup_bucket_arn,
    module.s3_storage.artifact_bucket_arn
  ]
  
  rds_resource_arns = [module.rds.db_instance_arn]
}

# Azure Resources
module "azure_fabric" {
  source = "./modules/azure-fabric"
  
  project_name        = var.project_name
  environment         = var.environment
  resource_group_name = "${var.project_name}-${var.environment}-rg"
  location           = "East US"
  
  fabric_workspace_name = "${var.project_name}-workspace"
  lakehouse_name       = "${var.project_name}-lakehouse"
  
  create_service_principal = true
}

# Cost Management
module "cost_management" {
  source = "./modules/cost-management"
  
  project_name = var.project_name
  environment  = var.environment
  
  monthly_budget_amount = 10000
  budget_alert_emails   = ["finance@solution-automater.com"]
  
  enable_cost_anomaly_detection = true
  enable_rightsizing_recommendations = true
}

# Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = module.rds.endpoint
  sensitive   = true
}

output "mongodb_nodes" {
  description = "MongoDB cluster nodes"
  value       = module.mongodb_cluster.node_ips
}

output "s3_backup_bucket" {
  description = "S3 backup bucket"
  value       = module.s3_storage.backup_bucket_name
}

output "fabric_workspace_id" {
  description = "Microsoft Fabric workspace ID"
  value       = module.azure_fabric.workspace_id
}

output "fabric_sql_endpoint" {
  description = "Microsoft Fabric SQL endpoint"
  value       = module.azure_fabric.sql_endpoint
  sensitive   = true
}