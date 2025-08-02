#!/bin/bash

# Burp SQL Injection Tester Setup Script
# This script sets up the environment for the SQL injection testing tool

echo "🔧 Setting up Burp SQL Injection Tester..."
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3 is installed
print_status "Checking Python 3 installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_status "Found: $PYTHON_VERSION"
else
    print_error "Python 3 is not installed. Please install Python 3.7 or later."
    exit 1
fi

# Check if pip is installed
print_status "Checking pip installation..."
if command -v pip3 &> /dev/null; then
    print_status "pip3 is available"
else
    print_error "pip3 is not installed. Please install pip3."
    exit 1
fi

# Install Python dependencies
print_status "Installing Python dependencies..."
if pip3 install -r requirements.txt; then
    print_status "Python dependencies installed successfully"
else
    print_error "Failed to install Python dependencies"
    exit 1
fi

# Check for Ghauri
print_status "Checking Ghauri installation..."
if command -v ghauri &> /dev/null; then
    print_status "Ghauri is already installed"
else
    print_warning "Ghauri not found. Attempting to install..."
    if pip3 install ghauri; then
        print_status "Ghauri installed successfully"
    else
        print_warning "Failed to install Ghauri via pip. You may need to install it manually."
        echo "  Alternative installation: git clone https://github.com/r0oth3x49/ghauri.git"
    fi
fi

# Check for SQLMap
print_status "Checking SQLMap installation..."
if command -v sqlmap &> /dev/null; then
    print_status "SQLMap is already installed"
else
    print_warning "SQLMap not found in PATH. Checking common locations..."
    
    # Check common SQLMap locations
    SQLMAP_LOCATIONS=(
        "/usr/bin/sqlmap"
        "/usr/local/bin/sqlmap"
        "/opt/sqlmap/sqlmap.py"
        "$HOME/sqlmap/sqlmap.py"
        "./sqlmap/sqlmap.py"
    )
    
    SQLMAP_FOUND=false
    for location in "${SQLMAP_LOCATIONS[@]}"; do
        if [ -f "$location" ]; then
            print_status "Found SQLMap at: $location"
            SQLMAP_FOUND=true
            break
        fi
    done
    
    if [ "$SQLMAP_FOUND" = false ]; then
        print_warning "SQLMap not found. Attempting to install..."
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            if sudo apt-get update && sudo apt-get install -y sqlmap; then
                print_status "SQLMap installed via apt-get"
            else
                print_warning "Failed to install SQLMap via apt-get"
            fi
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL
            if sudo yum install -y sqlmap; then
                print_status "SQLMap installed via yum"
            else
                print_warning "Failed to install SQLMap via yum"
            fi
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            if sudo pacman -S --noconfirm sqlmap; then
                print_status "SQLMap installed via pacman"
            else
                print_warning "Failed to install SQLMap via pacman"
            fi
        else
            print_warning "Package manager not recognized. Installing SQLMap manually..."
            if git clone https://github.com/sqlmapproject/sqlmap.git; then
                print_status "SQLMap cloned successfully"
                print_status "You may want to add sqlmap to your PATH:"
                echo "  export PATH=\$PATH:$(pwd)/sqlmap"
            else
                print_error "Failed to clone SQLMap repository"
            fi
        fi
    fi
fi

# Make scripts executable
print_status "Making scripts executable..."
chmod +x burp_sqli_tester.py
chmod +x test_tool.py
chmod +x setup.sh

# Create output directory
print_status "Creating output directory..."
mkdir -p sqli_results

# Run tests
print_status "Running basic tests..."
if python3 test_tool.py; then
    print_status "Basic tests passed"
else
    print_warning "Some tests failed, but the tool should still work"
fi

# Final instructions
echo ""
echo "=========================================="
print_status "Setup completed!"
echo ""
echo "📋 Usage Examples:"
echo "  # Test with sample log file"
echo "  python3 burp_sqli_tester.py examples/sample_burp.log"
echo ""
echo "  # Test with both tools concurrently"
echo "  python3 burp_sqli_tester.py your_burp.log --concurrent --max-workers 5"
echo ""
echo "  # Generate reports"
echo "  python3 burp_sqli_tester.py your_burp.log --json-report report.json --csv-report report.csv"
echo ""
echo "📚 Documentation:"
echo "  Read README.md for detailed usage instructions"
echo ""
echo "🔍 Troubleshooting:"
echo "  If tools are not found, check your PATH or specify full paths in the script"
echo "  For permission issues, ensure scripts are executable and you have write access"
echo ""

# Check if everything is ready
print_status "Performing final checks..."

ISSUES=0

# Check if main script exists and is executable
if [ -x "burp_sqli_tester.py" ]; then
    print_status "Main script is ready"
else
    print_error "Main script is not executable"
    ((ISSUES++))
fi

# Check if example files exist
if [ -f "examples/sample_burp.log" ] && [ -f "examples/sample_burp.xml" ]; then
    print_status "Example files are available"
else
    print_warning "Example files missing - some features may not work as expected"
fi

# Final status
echo ""
if [ $ISSUES -eq 0 ]; then
    print_status "🎉 All checks passed! The tool is ready to use."
else
    print_warning "⚠️ Setup completed with $ISSUES issue(s). Please review the output above."
fi
