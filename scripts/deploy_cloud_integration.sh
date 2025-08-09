#!/bin/bash

# Deploy Cloud Integration for Solution-Automater-Sandbox
# This script sets up the cloud integration components

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLOUD_CONFIG="${PROJECT_ROOT}/configs/cloud_integration_config.yaml"
VENV_PATH="${PROJECT_ROOT}/venv"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_warn "AWS CLI is not installed. Installing..."
        pip3 install awscli
    fi
    
    # Check Azure CLI
    if ! command -v az &> /dev/null; then
        log_warn "Azure CLI is not installed. Please install it manually."
    fi
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_warn "Terraform is not installed. Infrastructure deployment will be skipped."
    fi
}

setup_python_env() {
    log_info "Setting up Python environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_PATH" ]; then
        python3 -m venv "$VENV_PATH"
    fi
    
    # Activate virtual environment
    source "$VENV_PATH/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install required packages
    pip install -r - << EOF
boto3>=1.26.0
azure-identity>=1.14.0
azure-monitor-query>=1.2.0
azure-keyvault-secrets>=4.7.0
pyodbc>=4.0.39
pandas>=2.0.0
numpy>=1.24.0
pyyaml>=6.0
click>=8.1.0
tabulate>=0.9.0
cryptography>=41.0.0
sqlalchemy>=2.0.0
aioboto3>=11.0.0
cachetools>=5.3.0
EOF
    
    log_info "Python packages installed successfully"
}

check_cloud_credentials() {
    log_info "Checking cloud credentials..."
    
    # Check AWS credentials
    if aws sts get-caller-identity &> /dev/null; then
        log_info "AWS credentials are configured"
    else
        log_error "AWS credentials are not configured. Please run 'aws configure'"
        exit 1
    fi
    
    # Check Azure credentials
    if [ -z "${AZURE_TENANT_ID:-}" ] || [ -z "${AZURE_CLIENT_ID:-}" ] || [ -z "${AZURE_CLIENT_SECRET:-}" ]; then
        log_warn "Azure service principal credentials are not set. Fabric integration may not work."
        log_warn "Please set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET"
    fi
}

create_config_template() {
    log_info "Creating configuration template..."
    
    # Check if config exists
    if [ -f "$CLOUD_CONFIG" ]; then
        log_info "Configuration file already exists: $CLOUD_CONFIG"
        return
    fi
    
    # Create config directory
    mkdir -p "$(dirname "$CLOUD_CONFIG")"
    
    # Copy template
    cat > "$CLOUD_CONFIG" << 'EOF'
# Cloud Integration Configuration Template
# Replace ${VARIABLE} with actual values or set them as environment variables

organization: "Solution-Automater"
environment: "production"

providers:
  fabric:
    workspace_id: "${FABRIC_WORKSPACE_ID}"
    lakehouse_id: "${FABRIC_LAKEHOUSE_ID}"
    sql_endpoint: "${FABRIC_SQL_ENDPOINT}"
    tenant_id: "${AZURE_TENANT_ID}"
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"
    auth_method: "service_principal"

  aws:
    region: "us-east-1"
    profile: "default"
    s3_backup_bucket: "solution-automater-backups"
    s3_artifact_bucket: "solution-automater-artifacts"
    
    rds_connection_pools:
      main_db:
        host: "${RDS_MAIN_HOST}"
        port: 3306
        user: "${RDS_MAIN_USER}"
        password: "${RDS_MAIN_PASSWORD}"
        database: "${RDS_MAIN_DATABASE}"
        
    mongodb_clusters:
      primary_cluster:
        - "${MONGODB_NODE1}:27017"
        - "${MONGODB_NODE2}:27017"
        - "${MONGODB_NODE3}:27017"
EOF
    
    log_info "Configuration template created at: $CLOUD_CONFIG"
    log_warn "Please update the configuration with actual values"
}

setup_aws_resources() {
    log_info "Setting up AWS resources..."
    
    # Create S3 buckets if they don't exist
    BACKUP_BUCKET="solution-automater-backups"
    ARTIFACT_BUCKET="solution-automater-artifacts"
    
    # Check and create backup bucket
    if ! aws s3 ls "s3://${BACKUP_BUCKET}" 2>&1 | grep -q 'NoSuchBucket'; then
        log_info "Backup bucket already exists: ${BACKUP_BUCKET}"
    else
        log_info "Creating backup bucket: ${BACKUP_BUCKET}"
        aws s3 mb "s3://${BACKUP_BUCKET}" --region us-east-1
        
        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket "${BACKUP_BUCKET}" \
            --versioning-configuration Status=Enabled
            
        # Enable encryption
        aws s3api put-bucket-encryption \
            --bucket "${BACKUP_BUCKET}" \
            --server-side-encryption-configuration '{
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }'
    fi
    
    # Check and create artifact bucket
    if ! aws s3 ls "s3://${ARTIFACT_BUCKET}" 2>&1 | grep -q 'NoSuchBucket'; then
        log_info "Artifact bucket already exists: ${ARTIFACT_BUCKET}"
    else
        log_info "Creating artifact bucket: ${ARTIFACT_BUCKET}"
        aws s3 mb "s3://${ARTIFACT_BUCKET}" --region us-east-1
        
        # Enable versioning and encryption
        aws s3api put-bucket-versioning \
            --bucket "${ARTIFACT_BUCKET}" \
            --versioning-configuration Status=Enabled
            
        aws s3api put-bucket-encryption \
            --bucket "${ARTIFACT_BUCKET}" \
            --server-side-encryption-configuration '{
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }'
    fi
}

install_cli_commands() {
    log_info "Installing CLI commands..."
    
    # Create CLI wrapper script
    CLI_SCRIPT="${PROJECT_ROOT}/bin/cloud-cli"
    mkdir -p "$(dirname "$CLI_SCRIPT")"
    
    cat > "$CLI_SCRIPT" << EOF
#!/bin/bash
# Cloud Integration CLI wrapper

source "${VENV_PATH}/bin/activate"
export PYTHONPATH="${PROJECT_ROOT}/src:\$PYTHONPATH"
export CLOUD_CONFIG_FILE="${CLOUD_CONFIG}"

python -m cloud_integration.cli "\$@"
EOF
    
    chmod +x "$CLI_SCRIPT"
    
    log_info "CLI installed at: $CLI_SCRIPT"
    log_info "You can add ${PROJECT_ROOT}/bin to your PATH for easy access"
}

deploy_terraform() {
    log_info "Deploying infrastructure with Terraform..."
    
    if ! command -v terraform &> /dev/null; then
        log_warn "Terraform not installed. Skipping infrastructure deployment."
        return
    fi
    
    TERRAFORM_DIR="${PROJECT_ROOT}/infrastructure/terraform"
    
    if [ ! -d "$TERRAFORM_DIR" ]; then
        log_warn "Terraform configuration not found at: $TERRAFORM_DIR"
        return
    fi
    
    cd "$TERRAFORM_DIR"
    
    # Initialize Terraform
    log_info "Initializing Terraform..."
    terraform init
    
    # Plan deployment
    log_info "Planning infrastructure deployment..."
    terraform plan -out=tfplan
    
    # Ask for confirmation
    read -p "Do you want to apply the Terraform plan? (yes/no): " confirm
    if [ "$confirm" == "yes" ]; then
        log_info "Applying Terraform plan..."
        terraform apply tfplan
    else
        log_info "Terraform deployment cancelled"
    fi
    
    cd - > /dev/null
}

test_integration() {
    log_info "Testing cloud integration..."
    
    # Test AWS connection
    log_info "Testing AWS connection..."
    if aws s3 ls &> /dev/null; then
        log_info "AWS connection successful"
    else
        log_error "AWS connection failed"
    fi
    
    # Test CLI
    log_info "Testing CLI..."
    if "${PROJECT_ROOT}/bin/cloud-cli" --help &> /dev/null; then
        log_info "CLI is working"
    else
        log_error "CLI test failed"
    fi
}

print_next_steps() {
    cat << EOF

${GREEN}Cloud Integration Setup Complete!${NC}

Next steps:
1. Update the configuration file with your actual values:
   ${CLOUD_CONFIG}

2. Set up environment variables for sensitive data:
   export AZURE_TENANT_ID="your-tenant-id"
   export AZURE_CLIENT_ID="your-client-id"
   export AZURE_CLIENT_SECRET="your-client-secret"
   export FABRIC_WORKSPACE_ID="your-workspace-id"
   export FABRIC_LAKEHOUSE_ID="your-lakehouse-id"
   export FABRIC_SQL_ENDPOINT="your-sql-endpoint"

3. Add the CLI to your PATH:
   export PATH="${PROJECT_ROOT}/bin:\$PATH"

4. Test the integration:
   cloud-cli --help
   cloud-cli aws rds
   cloud-cli fabric tables
   cloud-cli cloud resources

5. Set up monitoring alerts:
   cloud-cli monitor alerts

6. Review security posture:
   cloud-cli security posture

For more information, see the documentation in the project repository.
EOF
}

# Main execution
main() {
    log_info "Starting Cloud Integration deployment..."
    
    check_requirements
    setup_python_env
    check_cloud_credentials
    create_config_template
    setup_aws_resources
    install_cli_commands
    
    # Optional: Deploy infrastructure
    read -p "Do you want to deploy cloud infrastructure with Terraform? (yes/no): " deploy_tf
    if [ "$deploy_tf" == "yes" ]; then
        deploy_terraform
    fi
    
    test_integration
    print_next_steps
    
    log_info "Deployment complete!"
}

# Run main function
main "$@"