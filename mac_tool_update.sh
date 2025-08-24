#!/bin/bash

# Ensure Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

echo "Updating Homebrew..."
brew update

# Install or upgrade Terraform
brew tap hashicorp/tap
brew install terraform || brew upgrade terraform

# Install or upgrade AWS CLI
brew install awscli || brew upgrade awscli

# Install or upgrade Python (3.x)
brew install python || brew upgrade python

# Upgrade pip and install boto3
pip3 install --upgrade pip
pip3 install boto3

# Confirm versions
echo ""
echo "Terraform version: $(terraform -version | head -n 1)"
echo "AWS CLI version: $(aws --version)"
echo "Python version: $(python3 --version)"
echo "Pip version: $(pip3 --version)"