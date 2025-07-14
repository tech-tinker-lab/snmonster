#!/bin/bash
# Ansible Setup and Management Script

set -e

echo "=== Ansible System Administration ==="

# Check if ansible is available
if ! command -v ansible &> /dev/null; then
    echo "📦 Installing Ansible..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y ansible
    elif command -v yum &> /dev/null; then
        sudo yum install -y ansible
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y ansible
    else
        echo "❌ Package manager not supported. Please install Ansible manually."
        exit 1
    fi
fi

# Create Ansible directory structure
ANSIBLE_DIR="/tmp/ansible_automation_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ANSIBLE_DIR"/{inventory,playbooks,roles,templates}

echo "📁 Ansible workspace created at: $ANSIBLE_DIR"

# Create inventory file
cat > "$ANSIBLE_DIR/inventory/hosts" << 'EOF'
[local]
localhost ansible_connection=local

[servers]
# Add your servers here
# server1 ansible_host=192.168.1.10 ansible_user=admin
# server2 ansible_host=192.168.1.11 ansible_user=admin

[webservers]
# Add web servers here
# web1 ansible_host=192.168.1.20 ansible_user=admin
# web2 ansible_host=192.168.1.21 ansible_user=admin

[dbservers]
# Add database servers here
# db1 ansible_host=192.168.1.30 ansible_user=admin

[all:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_become=yes
ansible_become_method=sudo
EOF

# Create ansible.cfg
cat > "$ANSIBLE_DIR/ansible.cfg" << 'EOF'
[defaults]
inventory = inventory/hosts
host_key_checking = False
timeout = 30
gathering = smart
fact_caching = memory
stdout_callback = yaml
bin_ansible_callbacks = True

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes
EOF

# Create system update playbook
cat > "$ANSIBLE_DIR/playbooks/system_update.yml" << 'EOF'
---
- name: System Update and Maintenance
  hosts: all
  become: yes
  tasks:
    - name: Update package cache (Ubuntu/Debian)
      apt:
        update_cache: yes
        cache_valid_time: 3600
      when: ansible_os_family == "Debian"

    - name: Update package cache (CentOS/RHEL)
      yum:
        update_cache: yes
      when: ansible_os_family == "RedHat"

    - name: Upgrade all packages (Ubuntu/Debian)
      apt:
        upgrade: yes
        autoremove: yes
      when: ansible_os_family == "Debian"

    - name: Upgrade all packages (CentOS/RHEL)
      yum:
        name: '*'
        state: latest
      when: ansible_os_family == "RedHat"

    - name: Clean up package cache
      shell: |
        if command -v apt-get &> /dev/null; then
          apt-get autoclean
        elif command -v yum &> /dev/null; then
          yum clean all
        fi
      args:
        warn: false

    - name: Check if reboot is required
      stat:
        path: /var/run/reboot-required
      register: reboot_required

    - name: Notify reboot required
      debug:
        msg: "⚠️  System reboot required on {{ inventory_hostname }}"
      when: reboot_required.stat.exists
EOF

# Create security hardening playbook
cat > "$ANSIBLE_DIR/playbooks/security_harden.yml" << 'EOF'
---
- name: Security Hardening
  hosts: all
  become: yes
  tasks:
    - name: Update SSH configuration
      template:
        src: sshd_config.j2
        dest: /etc/ssh/sshd_config
        backup: yes
      notify: restart ssh

    - name: Configure firewall (UFW for Ubuntu)
      ufw:
        state: enabled
        policy: deny
        rule: allow
        port: ssh
        proto: tcp
      when: ansible_os_family == "Debian"

    - name: Configure firewall (firewalld for CentOS)
      firewalld:
        service: ssh
        permanent: yes
        state: enabled
      when: ansible_os_family == "RedHat"

    - name: Install fail2ban (Ubuntu/Debian)
      apt:
        name: fail2ban
        state: present
      when: ansible_os_family == "Debian"

    - name: Install fail2ban (CentOS/RHEL)
      yum:
        name: fail2ban
        state: present
      when: ansible_os_family == "RedHat"

    - name: Start and enable fail2ban
      systemd:
        name: fail2ban
        state: started
        enabled: yes

    - name: Configure automatic security updates
      apt:
        name: unattended-upgrades
        state: present
      when: ansible_os_family == "Debian"

  handlers:
    - name: restart ssh
      systemd:
        name: ssh
        state: restarted
EOF

# Create monitoring setup playbook
cat > "$ANSIBLE_DIR/playbooks/monitoring_setup.yml" << 'EOF'
---
- name: Monitoring Setup
  hosts: all
  become: yes
  tasks:
    - name: Install monitoring tools
      package:
        name:
          - htop
          - iotop
          - nethogs
          - nload
          - iftop
        state: present

    - name: Create monitoring script
      copy:
        dest: /usr/local/bin/system_monitor.sh
        mode: '0755'
        content: |
          #!/bin/bash
          echo "=== System Monitor ==="
          echo "Date: $(date)"
          echo "Uptime: $(uptime)"
          echo "Load: $(cat /proc/loadavg)"
          echo "Memory: $(free -h)"
          echo "Disk: $(df -h)"
          echo "Network: $(ss -tuln | grep LISTEN)"

    - name: Setup log rotation for monitoring
      copy:
        dest: /etc/logrotate.d/system_monitor
        content: |
          /var/log/system_monitor.log {
            daily
            rotate 7
            compress
            delaycompress
            missingok
            notifempty
            create 644 root root
          }
EOF

# Create SSH template
cat > "$ANSIBLE_DIR/templates/sshd_config.j2" << 'EOF'
# SSH Configuration Template
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Security settings
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel INFO

# Other settings
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
EOF

# Create deployment playbook
cat > "$ANSIBLE_DIR/playbooks/deploy_app.yml" << 'EOF'
---
- name: Deploy Application
  hosts: webservers
  become: yes
  vars:
    app_name: "myapp"
    app_port: 8080
  tasks:
    - name: Create application directory
      file:
        path: /opt/{{ app_name }}
        state: directory
        owner: www-data
        group: www-data
        mode: '0755'

    - name: Copy application files
      copy:
        src: "{{ item }}"
        dest: /opt/{{ app_name }}/
        owner: www-data
        group: www-data
      with_fileglob:
        - "files/*"

    - name: Install application dependencies
      pip:
        requirements: /opt/{{ app_name }}/requirements.txt
        virtualenv: /opt/{{ app_name }}/venv
      when: ansible_os_family == "Debian"

    - name: Create systemd service
      template:
        src: app.service.j2
        dest: /etc/systemd/system/{{ app_name }}.service
        backup: yes
      notify: restart app

    - name: Start and enable application
      systemd:
        name: "{{ app_name }}"
        state: started
        enabled: yes

  handlers:
    - name: restart app
      systemd:
        name: "{{ app_name }}"
        state: restarted
EOF

# Create systemd service template
cat > "$ANSIBLE_DIR/templates/app.service.j2" << 'EOF'
[Unit]
Description={{ app_name }} Application
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/{{ app_name }}
ExecStart=/opt/{{ app_name }}/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Function to run playbook
run_playbook() {
    local playbook=$1
    local inventory=${2:-"inventory/hosts"}
    
    echo "🚀 Running playbook: $playbook"
    cd "$ANSIBLE_DIR"
    ansible-playbook -i "$inventory" "playbooks/$playbook.yml" -v
}

# Function to show help
show_help() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  setup                     - Setup Ansible environment"
    echo "  update                    - Run system update on all hosts"
    echo "  harden                    - Run security hardening"
    echo "  monitor                   - Setup monitoring"
    echo "  deploy <app>              - Deploy application"
    echo "  ping                      - Test connectivity to all hosts"
    echo "  facts                     - Gather facts from all hosts"
    echo "  help                      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup"
    echo "  $0 update"
    echo "  $0 harden"
    echo "  $0 deploy myapp"
}

# Main script logic
case "${1:-help}" in
    "setup")
        echo "✅ Ansible environment setup complete!"
        echo "📁 Workspace: $ANSIBLE_DIR"
        echo "📝 Edit inventory/hosts to add your servers"
        echo "🚀 Run '$0 update' to start automation"
        ;;
    "update")
        run_playbook "system_update"
        ;;
    "harden")
        run_playbook "security_harden"
        ;;
    "monitor")
        run_playbook "monitoring_setup"
        ;;
    "deploy")
        if [ -z "$2" ]; then
            echo "Please provide application name"
            exit 1
        fi
        # Update app name in playbook
        sed -i "s/app_name: \"myapp\"/app_name: \"$2\"/" "$ANSIBLE_DIR/playbooks/deploy_app.yml"
        run_playbook "deploy_app"
        ;;
    "ping")
        cd "$ANSIBLE_DIR"
        ansible all -m ping
        ;;
    "facts")
        cd "$ANSIBLE_DIR"
        ansible all -m setup
        ;;
    "help"|*)
        show_help
        ;;
esac 