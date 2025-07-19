# 🔒 Security Audit Features - User Guide

## Where to Find Security Audit Options

### 📍 **Location: ManagedDevices Page**
The security audit features are located in the **ManagedDevices** page of your application.

### 🎯 **Step-by-Step Guide:**

## 1. **Access the ManagedDevices Page**
   - Navigate to: `http://localhost:3000` (or your frontend URL)
   - Go to the **"Managed Devices"** section
   - You'll see a grid of device cards

## 2. **Select Devices for Security Audit**
   ### Method 1: Individual Selection
   - **Click on device cards** to select them
   - Selected cards will show a **blue border** and **checkmark icon**
   - You can select multiple devices
   
   ### Method 2: Bulk Selection
   - Use **"Select All"** button to select all devices
   - Use **"Clear All"** button to deselect all devices

## 3. **Run Security Audit**
   ### Option A: Bulk Actions Menu
   - After selecting devices, click **"Bulk Actions"** button
   - Choose **"Run Security Audit"** from the dropdown menu
   - This will initiate security audits on selected devices
   
   ### Option B: View Security Reports Button
   - Click the **"View Security Reports"** button (always visible)
   - This will show existing audit data or prompt to run audits

## 4. **View Detailed Security Reports**
   ### After running audits, you'll see:
   
   #### 📊 **Summary Dashboard**
   - **Total Devices Audited**: Count of devices with audit data
   - **Average Security Score**: Overall security posture
   - **Critical Issues**: Total critical security issues found
   
   #### 📋 **Individual Device Reports**
   Each device shows:
   - **Overall Security Score** (0-100)
   - **Category Breakdown**:
     - System Updates Score
     - Network Security Score  
     - User Accounts Score
     - File Permissions Score
   - **Critical Issues** and **Warnings** count
   - **Detailed Analysis** for each category
   - **Security Recommendations**
   
   #### 🔍 **Raw Audit Data**
   - System information
   - Network analysis
   - Security logs analysis
   - AI-generated summary

## 5. **Track Security Posture Over Time**
   ### Historical Data Features:
   - **Audit History**: Each audit is timestamped and stored
   - **Score Trends**: Compare current vs previous audit scores
   - **Issue Tracking**: Monitor resolution of security issues
   - **Compliance Monitoring**: Track security improvements

### 🚀 **Quick Start:**
1. **Set SSH Credentials**: Select devices → Bulk Actions → "Set SSH Credentials"
2. **Run Security Audit**: Select devices → Bulk Actions → "Run Security Audit"  
3. **View Reports**: Click "View Security Reports" button
4. **Track Progress**: Re-run audits periodically to track improvements

### 🎨 **Visual Indicators:**
- **Green Score**: 80+ (Good security posture)
- **Yellow Score**: 60-79 (Needs attention)
- **Red Score**: <60 (Critical security issues)
- **Progress Bars**: Visual representation of category scores
- **Issue Badges**: Critical issues and warnings counts

### 📈 **Sample Security Report Structure:**
```
Device: 192.168.1.75 (rock-5b)
Overall Score: 78/100
Audit Date: 2025-07-19T10:30:00Z

Categories:
├── System Updates: 85% (2 critical, 5 warnings)
├── Network Security: 72% (1 critical, 3 warnings)  
├── User Accounts: 90% (0 critical, 1 warning)
└── File Permissions: 88% (0 critical, 2 warnings)

Recommendations:
• Install pending security updates immediately
• Close unnecessary ports (8080, 3000)
• Review failed login attempts
• Update system packages regularly
```

This comprehensive security audit system provides enterprise-grade security monitoring for your managed devices!
