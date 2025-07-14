#!/bin/bash
# Kubernetes Context and Namespace Management Script

set -e

echo "=== Kubernetes Context & Namespace Manager ==="

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl first."
    exit 1
fi

# Function to display current context
show_current_context() {
    echo "🔍 Current Context Information:"
    echo "Context: $(kubectl config current-context)"
    echo "Namespace: $(kubectl config view --minify --output 'jsonpath={..namespace}' 2>/dev/null || echo 'default')"
    echo "Cluster: $(kubectl config view --minify --output 'jsonpath={..cluster}' 2>/dev/null || echo 'N/A')"
    echo "User: $(kubectl config view --minify --output 'jsonpath={..user}' 2>/dev/null || echo 'N/A')"
}

# Function to list all contexts
list_contexts() {
    echo "📋 Available Kubernetes Contexts:"
    kubectl config get-contexts
}

# Function to list all namespaces
list_namespaces() {
    echo "📋 Available Namespaces:"
    kubectl get namespaces
}

# Function to switch context
switch_context() {
    local context_name=$1
    if [ -z "$context_name" ]; then
        echo "Please provide a context name"
        return 1
    fi
    
    echo "🔄 Switching to context: $context_name"
    kubectl config use-context "$context_name"
    show_current_context
}

# Function to switch namespace
switch_namespace() {
    local namespace_name=$1
    if [ -z "$namespace_name" ]; then
        echo "Please provide a namespace name"
        return 1
    fi
    
    echo "🔄 Switching to namespace: $namespace_name"
    kubectl config set-context --current --namespace="$namespace_name"
    show_current_context
}

# Function to create namespace
create_namespace() {
    local namespace_name=$1
    if [ -z "$namespace_name" ]; then
        echo "Please provide a namespace name"
        return 1
    fi
    
    echo "➕ Creating namespace: $namespace_name"
    kubectl create namespace "$namespace_name"
    echo "✅ Namespace '$namespace_name' created successfully"
}

# Function to delete namespace
delete_namespace() {
    local namespace_name=$1
    if [ -z "$namespace_name" ]; then
        echo "Please provide a namespace name"
        return 1
    fi
    
    echo "⚠️  Are you sure you want to delete namespace '$namespace_name'? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "🗑️  Deleting namespace: $namespace_name"
        kubectl delete namespace "$namespace_name"
        echo "✅ Namespace '$namespace_name' deleted successfully"
    else
        echo "❌ Namespace deletion cancelled"
    fi
}

# Function to show cluster info
show_cluster_info() {
    echo "🏢 Cluster Information:"
    kubectl cluster-info
    
    echo -e "\n📊 Node Information:"
    kubectl get nodes -o wide
    
    echo -e "\n📦 Pod Information:"
    kubectl get pods --all-namespaces
}

# Function to show resource usage
show_resource_usage() {
    echo "📈 Resource Usage:"
    
    echo -e "\n💾 Memory Usage by Pod:"
    kubectl top pods --all-namespaces --sort-by=memory
    
    echo -e "\n⚡ CPU Usage by Pod:"
    kubectl top pods --all-namespaces --sort-by=cpu
    
    echo -e "\n🖥️  Node Resource Usage:"
    kubectl top nodes
}

# Function to show security context
show_security_context() {
    echo "🔒 Security Context:"
    
    echo -e "\n👥 Service Accounts:"
    kubectl get serviceaccounts --all-namespaces
    
    echo -e "\n🔐 Secrets:"
    kubectl get secrets --all-namespaces
    
    echo -e "\n🛡️  Network Policies:"
    kubectl get networkpolicies --all-namespaces
}

# Function to backup context
backup_context() {
    local backup_file="k8s_context_backup_$(date +%Y%m%d_%H%M%S).yaml"
    echo "💾 Backing up current context to: $backup_file"
    kubectl config view --raw > "$backup_file"
    echo "✅ Context backed up to: $backup_file"
}

# Function to show help
show_help() {
    echo "Usage: $0 [COMMAND] [ARGUMENTS]"
    echo ""
    echo "Commands:"
    echo "  current                    - Show current context and namespace"
    echo "  contexts                   - List all available contexts"
    echo "  namespaces                 - List all namespaces"
    echo "  switch-context <name>      - Switch to specified context"
    echo "  switch-ns <name>           - Switch to specified namespace"
    echo "  create-ns <name>           - Create new namespace"
    echo "  delete-ns <name>           - Delete namespace"
    echo "  cluster-info               - Show cluster information"
    echo "  resources                  - Show resource usage"
    echo "  security                   - Show security context"
    echo "  backup                     - Backup current context"
    echo "  help                       - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 current"
    echo "  $0 switch-context production"
    echo "  $0 switch-ns monitoring"
    echo "  $0 create-ns new-app"
}

# Main script logic
case "${1:-help}" in
    "current")
        show_current_context
        ;;
    "contexts")
        list_contexts
        ;;
    "namespaces")
        list_namespaces
        ;;
    "switch-context")
        switch_context "$2"
        ;;
    "switch-ns")
        switch_namespace "$2"
        ;;
    "create-ns")
        create_namespace "$2"
        ;;
    "delete-ns")
        delete_namespace "$2"
        ;;
    "cluster-info")
        show_cluster_info
        ;;
    "resources")
        show_resource_usage
        ;;
    "security")
        show_security_context
        ;;
    "backup")
        backup_context
        ;;
    "help"|*)
        show_help
        ;;
esac 