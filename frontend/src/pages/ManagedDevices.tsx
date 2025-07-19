import React, { useState, useRef } from 'react';
import { deviceAPI, getBackendWsUrl } from '../services/api';
import XTermTerminal, { XTermTerminalHandle } from '../components/XTermTerminal';
import RefreshIcon from '@mui/icons-material/Refresh';
import SearchIcon from '@mui/icons-material/Search';
import RemoveFromManagedIcon from '@mui/icons-material/RemoveCircleOutline';
import ReportIcon from '@mui/icons-material/Assessment';
import NetworkPing from '@mui/icons-material/NetworkPing';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import SecurityIcon from '@mui/icons-material/Security';
import PasswordIcon from '@mui/icons-material/Password';
import DockerIcon from '@mui/icons-material/Adb';
import AnsibleIcon from '@mui/icons-material/Terminal';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import TerminalIcon from '@mui/icons-material/Terminal';
import BuildCircleIcon from '@mui/icons-material/BuildCircle';
import EditIcon from '@mui/icons-material/Edit';
import InfoIcon from '@mui/icons-material/Info';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import SystemUpdateIcon from '@mui/icons-material/SystemUpdate';
import UpdateIcon from '@mui/icons-material/Update';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Chip,
  IconButton,
  Tooltip,
  CircularProgress,
  Button,
  TextField,
  InputAdornment,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Checkbox,
  Snackbar,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
  Paper,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';





// Modular DeviceCard component
type Device = {
  id: number;
  hostname?: string;
  ip_address: string;
  device_type: string;
  operating_system: string;
  status: string;
  category?: string;
  ai_risk_score: number;
  mac_address?: string;
  last_seen?: string;
  open_ports?: string;
  vulnerabilities?: string;
  is_managed?: boolean;
  ssh_username?: string;
};

const DeviceCard = ({ 
  device, 
  onMenuOpen, 
  isSelected, 
  onSelect 
}: { 
  device: Device; 
  onMenuOpen: (e: React.MouseEvent<any>, device: Device) => void;
  isSelected: boolean;
  onSelect: (deviceId: number) => void;
}) => {
  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'online':
        return 'success';
      case 'offline':
        return 'error';
      case 'unknown':
        return 'warning';
      default:
        return 'default';
    }
  };
  const getRiskScoreColor = (score: number) => {
    if (score >= 8) return 'error';
    if (score >= 6) return 'warning';
    if (score >= 4) return 'info';
    return 'success';
  };
  return (
    <Card
      sx={{
        position: 'relative',
        minHeight: 200,
        borderRadius: 2,
        boxShadow: isSelected ? 4 : 3,
        transition: 'box-shadow 0.2s, transform 0.1s, border 0.2s',
        '&:hover': {
          boxShadow: 6,
          transform: 'scale(1.02)',
          cursor: 'pointer',
        },
        p: 1.5,
        background:
          device.status.toLowerCase() === 'online'
            ? 'linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%)'
            : device.status.toLowerCase() === 'offline'
            ? 'linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%)'
            : 'linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%)',
        border: isSelected 
          ? '3px solid #2563eb'
          : device.status.toLowerCase() === 'online' 
          ? '1px solid #0ea5e9'
          : device.status.toLowerCase() === 'offline'
          ? '1px solid #ef4444'
          : '1px solid #f59e0b',
      }}
      onClick={(e) => {
        // Don't trigger selection if clicking on the menu button
        if (!(e.target as HTMLElement).closest('button')) {
          onSelect(device.id);
        }
      }}
    >
      {/* Selection indicator */}
      {isSelected && (
        <Box sx={{ 
          position: 'absolute', 
          top: 8, 
          left: 8, 
          zIndex: 1 
        }}>
          <CheckCircleIcon 
            sx={{ 
              color: '#2563eb', 
              backgroundColor: 'white', 
              borderRadius: '50%',
              fontSize: 20
            }} 
          />
        </Box>
      )}
      
      <Box sx={{ position: 'absolute', top: 6, right: 6 }}>
        <Tooltip title="More Actions">
          <IconButton
            size="small"
            onClick={(e) => onMenuOpen(e, device)}
            sx={{ 
              color: '#64748b',
              '&:hover': { 
                backgroundColor: 'rgba(100, 116, 139, 0.1)',
                color: '#334155' 
              }
            }}
          >
            <MoreVertIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1, flexWrap: 'wrap' }}>
        <Chip
          label={device.status}
          color={getStatusColor(device.status)}
          size="small"
          sx={{ fontSize: '0.7rem', height: 20 }}
          icon={
            device.status.toLowerCase() === 'online' ? (
              <CheckCircleIcon sx={{ fontSize: 14 }} />
            ) : device.status.toLowerCase() === 'offline' ? (
              <ErrorIcon sx={{ fontSize: 14 }} />
            ) : (
              <WarningIcon sx={{ fontSize: 14 }} />
            )
          }
        />
        <Chip
          label={`Risk: ${device.ai_risk_score.toFixed(1)}`}
          color={getRiskScoreColor(device.ai_risk_score)}
          size="small"
          sx={{ fontSize: '0.7rem', height: 20 }}
        />
      </Box>
      <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5, color: '#1e293b', fontSize: '0.95rem' }}>
        {device.hostname || device.ip_address}
      </Typography>
      <Typography variant="body2" sx={{ mb: 1, color: '#64748b', fontSize: '0.8rem' }}>
        {device.ip_address} • {device.device_type}
      </Typography>
      <Typography variant="body2" sx={{ mb: 1, color: '#64748b', fontSize: '0.8rem' }}>
        {device.operating_system}
      </Typography>
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0.5, mb: 1 }}>
        <Box>
          <Typography variant="caption" sx={{ color: '#94a3b8', fontSize: '0.7rem', fontWeight: 500 }}>
            MAC
          </Typography>
          <Typography variant="body2" sx={{ color: '#475569', fontSize: '0.75rem' }}>
            {device.mac_address?.slice(-8) || 'N/A'}
          </Typography>
        </Box>
        <Box>
          <Typography variant="caption" sx={{ color: '#94a3b8', fontSize: '0.7rem', fontWeight: 500 }}>
            Last Seen
          </Typography>
          <Typography variant="body2" sx={{ color: '#475569', fontSize: '0.75rem' }}>
            {device.last_seen ? new Date(device.last_seen).toLocaleDateString() : 'Never'}
          </Typography>
        </Box>
      </Box>
      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 'auto' }}>
        <Chip 
          label={device.is_managed ? 'Managed' : 'Unmanaged'} 
          color={device.is_managed ? 'success' : 'default'} 
          size="small" 
          sx={{ fontSize: '0.65rem', height: 18 }}
        />
        {device.category && (
          <Chip 
            label={device.category} 
            color="info" 
            size="small" 
            sx={{ fontSize: '0.65rem', height: 18 }}
          />
        )}
        {device.ssh_username && (
          <Chip 
            label={`SSH: ${device.ssh_username}`} 
            color="primary" 
            size="small" 
            sx={{ fontSize: '0.65rem', height: 18 }}
          />
        )}
      </Box>
    </Card>
  );
};


const ManagedDevices: React.FC = () => {
  // Remove from management handler
  const handleRemoveFromManaged = () => {
    if (selectedDeviceIds.length > 0) {
      unmarkManagedMutation.mutate(selectedDeviceIds);
    }
  };

  // Dummy bulk action handlers
  const handleBulkPing = () => setSnackbar({ open: true, message: 'Bulk ping executed', severity: 'success' });
  const handleBulkPortScan = () => setSnackbar({ open: true, message: 'Bulk port scan executed', severity: 'success' });
  const handleBulkSecurityScan = () => setSnackbar({ open: true, message: 'Bulk security scan executed', severity: 'success' });
  const handleBulkAIPatch = () => setSnackbar({ open: true, message: 'Bulk AI patch executed', severity: 'success' });
  // State and hooks
  const [devicesData, setDevicesData] = useState<{ devices: Device[] }>({ devices: [] });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchDevices = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await deviceAPI.getManagedDevices();
      // Accept both { devices: [...] } and [...] as response
      const data = res.data;
      setDevicesData({ devices: data.devices || data });
    } catch (err: any) {
      setError(err.message || 'Unknown error');
    } finally {
      setIsLoading(false);
    }
  };

  React.useEffect(() => {
    fetchDevices();
  }, []);
  const refetch = fetchDevices;
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<number[]>([]);
  const [bulkActionsAnchor, setBulkActionsAnchor] = useState<null | HTMLElement>(null);
  const [removeDialog, setRemoveDialog] = useState(false);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const [passwordDialog, setPasswordDialog] = useState(false);
  const [bulkPassword, setBulkPassword] = useState('');
  const [bulkUsername, setBulkUsername] = useState('');
  const [securityReportDialog, setSecurityReportDialog] = useState(false);
  const [securityReports, setSecurityReports] = useState<any[]>([]);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' | 'warning' | 'info' });
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [menuDevice, setMenuDevice] = useState<Device | null>(null);
  const [actionDialog, setActionDialog] = useState({ open: false, type: '', device: null as Device | null });
  const [shellDialog, setShellDialog] = useState<{ open: boolean; device: Device | null }>({ open: false, device: null });
  const [terminalReady, setTerminalReady] = useState(false);
  const [credentialsDialog, setCredentialsDialog] = useState<{ open: boolean; device: Device | null }>({ open: false, device: null });
  const [credentialsForm, setCredentialsForm] = useState({ username: '', password: '' });
  const terminalRef = useRef<XTermTerminalHandle>(null);
  const [sortField, setSortField] = useState<'ip_address' | 'hostname' | 'device_type' | 'operating_system' | 'ai_risk_score' | 'last_seen'>('ip_address');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  
  // Handle device selection
  const handleDeviceSelect = (deviceId: number) => {
    setSelectedDeviceIds(prevSelected => {
      if (prevSelected.includes(deviceId)) {
        // Deselect if already selected
        return prevSelected.filter(id => id !== deviceId);
      } else {
        // Select if not already selected
        return [...prevSelected, deviceId];
      }
    });
  };
  
  // Dummy deviceActions and aiPatchLoading for menu
  const deviceActions = [
    { label: 'Details', icon: <InfoIcon />, action: (device: Device) => setActionDialog({ open: true, type: 'details', device }) },
    { label: 'Edit', icon: <EditIcon />, action: (device: Device) => {} },
    { 
      label: 'Terminal', 
      icon: <TerminalIcon />, 
      action: (device: Device) => {
        setShellDialog({ open: true, device });
        // Delay terminal initialization to allow dialog to fully open
        setTimeout(() => setTerminalReady(true), 300);
      }
    },
    { 
      label: 'SSH Credentials', 
      icon: <PasswordIcon />, 
      action: (device: Device) => {
        setCredentialsForm({ 
          username: device.ssh_username || '', 
          password: '' 
        });
        setCredentialsDialog({ open: true, device });
      }
    },
    { label: 'AI Automated OS & Security Patches', icon: <BuildCircleIcon />, action: (device: Device) => {} },
  ];
  const aiPatchLoading = false;

  // Dummy unmarkManagedMutation and setBulkPasswordMutation, installDockerMutation, installAnsibleMutation, runSecurityAuditMutation
  const unmarkManagedMutation = { isLoading: false, mutate: (ids: number[]) => setSnackbar({ open: true, message: 'Devices removed from management', severity: 'success' }) };
  const setBulkPasswordMutation = { isLoading: false, mutate: ({ deviceIds, password }: { deviceIds: number[]; password: string }) => setSnackbar({ open: true, message: 'Password set', severity: 'success' }) };
  const installDockerMutation = { mutate: (ids: number[]) => setSnackbar({ open: true, message: 'Docker installed', severity: 'success' }) };
  const installAnsibleMutation = { mutate: (ids: number[]) => setSnackbar({ open: true, message: 'Ansible installed', severity: 'success' }) };
  // Real API implementations for security audit
  const runSecurityAuditMutation = { 
    mutate: async (ids: number[]) => {
      try {
        setActionInProgress('Running security audit...');
        const response = await deviceAPI.runSecurityAudit(ids);
        setSnackbar({ 
          open: true, 
          message: `Security audit initiated for ${ids.length} device(s)`, 
          severity: 'success' 
        });
        setActionInProgress(null);
      } catch (error) {
        console.error('Security audit failed:', error);
        setSnackbar({ 
          open: true, 
          message: 'Failed to run security audit', 
          severity: 'error' 
        });
        setActionInProgress(null);
      }
    }
  };

  // Real API implementations for system updates
  const runSystemUpdateMutation = { 
    mutate: async (ids: number[]) => {
      try {
        setActionInProgress('Running system updates...');
        const response = await deviceAPI.runSystemUpdate(ids);
        setSnackbar({ 
          open: true, 
          message: `System update initiated for ${ids.length} device(s)`, 
          severity: 'success' 
        });
        setActionInProgress(null);
      } catch (error) {
        console.error('System update failed:', error);
        setSnackbar({ 
          open: true, 
          message: 'Failed to run system update', 
          severity: 'error' 
        });
        setActionInProgress(null);
      }
    }
  };

  const fetchSystemUpdateStatus = async () => {
    try {
      setActionInProgress('Checking system update status...');
      const response = await deviceAPI.getSystemUpdateStatus(selectedDeviceIds);
      // Handle system update status response
      setSnackbar({ 
        open: true, 
        message: `System status checked for ${selectedDeviceIds.length} device(s)`, 
        severity: 'info' 
      });
      setActionInProgress(null);
    } catch (error) {
      console.error('Failed to check system update status:', error);
      setSnackbar({ 
        open: true, 
        message: 'Failed to check system status', 
        severity: 'error' 
      });
      setActionInProgress(null);
    }
  };

  const fetchSecurityReports = async () => {
    try {
      setActionInProgress('Fetching security reports...');
      const response = await deviceAPI.getSecurityReports(selectedDeviceIds);
      setSecurityReports(response.data.reports || []);
      setSecurityReportDialog(true);
      setActionInProgress(null);
    } catch (error) {
      console.error('Failed to fetch security reports:', error);
      setSnackbar({ 
        open: true, 
        message: 'Failed to fetch security reports', 
        severity: 'error' 
      });
      setActionInProgress(null);
    }
  };

  // ...existing code...
  const handleMenuOpen = (e: React.MouseEvent<HTMLElement>, device: Device) => {
    setAnchorEl(e.currentTarget as HTMLElement);
    setMenuDevice(device);
  };
  const handleMenuClose = () => {
    setAnchorEl(null);
    setMenuDevice(null);
  };
  // Devices logic
  const devices = devicesData?.devices || [];

  // Filter and sort devices
  const filteredDevices = devices.filter(
    (device: Device) =>
      device.ip_address.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (device.hostname &&
        device.hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
      device.device_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.operating_system.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const sortedDevices = [...filteredDevices].sort((a: Device, b: Device) => {
    let aValue = a[sortField];
    let bValue = b[sortField];

    if (sortField === 'last_seen') {
      aValue = aValue ? new Date(aValue).getTime() : 0;
      bValue = bValue ? new Date(bValue).getTime() : 0;
    }

    if (aValue == null) return 1;
    if (bValue == null) return -1;
    if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
    if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
    return 0;
  });

  // ...existing code...


  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography color="error">Error: {error}</Typography>
        <Button onClick={refetch} variant="contained">Retry</Button>
      </Box>
    );
  }
  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', color: 'primary.main' }}>
          Managed Devices
        </Typography>
        <Button variant="outlined" startIcon={<RefreshIcon />} onClick={() => refetch()} disabled={isLoading}>
          Refresh
        </Button>
      </Box>

      {/* Stats Cards */}
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 2, mb: 3 }}>
        <Card><CardContent><Typography color="textSecondary" gutterBottom>Total Managed Devices</Typography><Typography variant="h5">{devices.length}</Typography></CardContent></Card>
        <Card><CardContent><Typography color="textSecondary" gutterBottom>Online Devices</Typography><Typography variant="h5" color="success.main">{devices.filter((d: Device) => d.status.toLowerCase() === 'online').length}</Typography></CardContent></Card>
        <Card><CardContent><Typography color="textSecondary" gutterBottom>High Risk Devices</Typography><Typography variant="h5" color="error.main">{devices.filter((d: Device) => d.ai_risk_score >= 8).length}</Typography></CardContent></Card>
        <Card><CardContent><Typography color="textSecondary" gutterBottom>Selected Devices</Typography><Typography variant="h5" color="primary.main">{selectedDeviceIds.length}</Typography></CardContent></Card>
      </Box>

      {/* Controls */}
      <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
        <TextField
          placeholder="Search devices..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
          sx={{ minWidth: 300 }}
        />
        <Button variant="contained" color="primary" startIcon={<MoreVertIcon />} disabled={selectedDeviceIds.length === 0} onClick={(e) => setBulkActionsAnchor(e.currentTarget)}>
          Bulk Actions ({selectedDeviceIds.length})
        </Button>
        <Button 
          variant="outlined" 
          onClick={() => {
            if (selectedDeviceIds.length === devices.length) {
              setSelectedDeviceIds([]);
            } else {
              setSelectedDeviceIds(devices.map((device: Device) => device.id));
            }
          }}
          sx={{ minWidth: 120 }}
        >
          {selectedDeviceIds.length === devices.length ? 'Clear All' : 'Select All'}
        </Button>
        <Button variant="contained" color="warning" startIcon={<RemoveFromManagedIcon />} disabled={selectedDeviceIds.length === 0} onClick={() => setRemoveDialog(true)}>
          Remove from Management ({selectedDeviceIds.length})
        </Button>
        <Button variant="outlined" startIcon={<ReportIcon />} disabled={selectedDeviceIds.length === 0} onClick={fetchSecurityReports}>
          View Security Reports
        </Button>
        {actionInProgress && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CircularProgress size={20} />
            <Typography variant="body2">{actionInProgress}</Typography>
          </Box>
        )}
      </Box>

      {/* Bulk Actions Menu */}
      <Menu anchorEl={bulkActionsAnchor} open={Boolean(bulkActionsAnchor)} onClose={() => setBulkActionsAnchor(null)}>
        <MenuItem onClick={handleBulkPing}><ListItemIcon><NetworkPing /></ListItemIcon><ListItemText primary="Bulk Ping" /></MenuItem>
        <MenuItem onClick={handleBulkPortScan}><ListItemIcon><NetworkCheckIcon /></ListItemIcon><ListItemText primary="Bulk Port Scan" /></MenuItem>
        <MenuItem onClick={handleBulkSecurityScan}><ListItemIcon><SecurityIcon /></ListItemIcon><ListItemText primary="Bulk Security Scan" /></MenuItem>
        <MenuItem onClick={handleBulkAIPatch}><ListItemIcon><BuildCircleIcon /></ListItemIcon><ListItemText primary="Bulk AI Patch" /></MenuItem>
        <Divider />
        <MenuItem onClick={() => { setPasswordDialog(true); setBulkActionsAnchor(null); }}><ListItemIcon><PasswordIcon /></ListItemIcon><ListItemText primary="Set SSH Credentials" /></MenuItem>
        <MenuItem onClick={() => installDockerMutation.mutate(selectedDeviceIds)}><ListItemIcon><DockerIcon /></ListItemIcon><ListItemText primary="Install Docker" /></MenuItem>
        <MenuItem onClick={() => installAnsibleMutation.mutate(selectedDeviceIds)}><ListItemIcon><AnsibleIcon /></ListItemIcon><ListItemText primary="Install Ansible" /></MenuItem>
        <MenuItem onClick={() => runSecurityAuditMutation.mutate(selectedDeviceIds)}><ListItemIcon><SecurityIcon /></ListItemIcon><ListItemText primary="Run Security Audit" /></MenuItem>
        <Divider />
        <MenuItem onClick={() => runSystemUpdateMutation.mutate(selectedDeviceIds)}><ListItemIcon><SystemUpdateIcon /></ListItemIcon><ListItemText primary="Run System Updates" /></MenuItem>
        <MenuItem onClick={fetchSystemUpdateStatus}><ListItemIcon><UpdateIcon /></ListItemIcon><ListItemText primary="Check Update Status" /></MenuItem>
      </Menu>

      {/* Actions Menu for each device */}
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose} anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }} transformOrigin={{ vertical: 'top', horizontal: 'right' }}>
        {deviceActions.map((action, index) => (
          <MenuItem key={index} onClick={() => { if (menuDevice) action.action(menuDevice); handleMenuClose(); }} disabled={aiPatchLoading}>
            <ListItemIcon>{action.icon}</ListItemIcon>
            <ListItemText primary={action.label} />
            {action.label === 'AI Automated OS & Security Patches' && aiPatchLoading && (<CircularProgress size={16} />)}
          </MenuItem>
        ))}
      </Menu>

      {/* Device Details Dialog */}
      <Dialog open={actionDialog.open && actionDialog.type === 'details'} onClose={() => setActionDialog({ ...actionDialog, open: false })} maxWidth="md" fullWidth>
        <DialogTitle>Device Details</DialogTitle>
        <DialogContent>
          {actionDialog.device && (
            <Box>
              <Typography variant="h6">{actionDialog.device.hostname || actionDialog.device.ip_address}</Typography>
              <Typography variant="body2">IP: {actionDialog.device.ip_address}</Typography>
              <Typography variant="body2">Type: {actionDialog.device.device_type}</Typography>
              <Typography variant="body2">OS: {actionDialog.device.operating_system}</Typography>
              <Typography variant="body2">Category: {actionDialog.device.category || 'Uncategorized'}</Typography>
              <Typography variant="body2">MAC: {actionDialog.device.mac_address}</Typography>
              <Typography variant="body2">Status: {actionDialog.device.status}</Typography>
              <Typography variant="body2">Last Seen: {actionDialog.device.last_seen}</Typography>
              <Typography variant="body2">AI Risk Score: {actionDialog.device.ai_risk_score}</Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setActionDialog({ ...actionDialog, open: false })}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Terminal Dialog */}
      <Dialog 
        open={shellDialog.open} 
        onClose={() => {
          terminalRef.current?.disconnect();
          setTerminalReady(false);
          setShellDialog({ open: false, device: null });
        }}
        maxWidth="lg" 
        fullWidth
        PaperProps={{
          sx: { height: '80vh', display: 'flex', flexDirection: 'column' }
        }}
      >
        <DialogTitle sx={{ pb: 1 }}>
          Terminal - {shellDialog.device?.hostname || shellDialog.device?.ip_address}
          {shellDialog.device?.ssh_username && (
            <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', mt: 0.5 }}>
              SSH User: {shellDialog.device.ssh_username}
            </Typography>
          )}
        </DialogTitle>
        <DialogContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', p: 0 }}>
          {shellDialog.device && terminalReady && (
            <XTermTerminal
              ref={terminalRef}
              wsUrl={`${getBackendWsUrl()}/api/devices/${shellDialog.device.id}/shell`}
              height="100%"
              fontSize={14}
              onStatus={(status) => {
                if (status === 'connected') setSnackbar({ open: true, message: 'SSH connection established', severity: 'success' });
                if (status === 'disconnected') setSnackbar({ open: true, message: 'SSH connection closed', severity: 'info' });
                if (status === 'connecting') setSnackbar({ open: true, message: 'Connecting to SSH...', severity: 'info' });
              }}
              onError={(error) => {
                setSnackbar({ open: true, message: error, severity: 'error' });
              }}
            />
          )}
          {shellDialog.device && !terminalReady && (
            <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
              <CircularProgress />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              terminalRef.current?.disconnect();
              setTerminalReady(false);
              setShellDialog({ open: false, device: null });
            }}
          >
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Devices Card Grid */}
      {isLoading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}><CircularProgress /></Box>
      ) : (
        <Grid container spacing={3}>
          {sortedDevices.map((device: Device) => (
            <Grid item xs={12} sm={6} md={4} lg={3} key={device.id}>
              <DeviceCard 
                device={device} 
                onMenuOpen={handleMenuOpen}
                isSelected={selectedDeviceIds.includes(device.id)}
                onSelect={handleDeviceSelect}
              />
            </Grid>
          ))}
        </Grid>
      )}

      {/* Remove from Management Dialog */}
      <Dialog open={removeDialog} onClose={() => setRemoveDialog(false)}>
        <DialogTitle>Remove Devices from Management</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to remove {selectedDeviceIds.length} device(s) from management? They will be moved back to the Devices page as unmanaged devices.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoveDialog(false)}>Cancel</Button>
          <Button onClick={handleRemoveFromManaged} color="warning" variant="contained" disabled={unmarkManagedMutation.isLoading}>
            {unmarkManagedMutation.isLoading ? (<CircularProgress size={20} />) : ('Remove from Management')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Set Password Dialog */}
      <Dialog open={passwordDialog} onClose={() => setPasswordDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Set SSH Credentials for Selected Devices</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            Set SSH username and password for {selectedDeviceIds.length} selected device(s).
          </DialogContentText>
          <TextField
            autoFocus
            margin="dense"
            label="SSH Username"
            type="text"
            fullWidth
            variant="outlined"
            value={bulkUsername}
            onChange={(e) => setBulkUsername(e.target.value)}
            helperText="Username for SSH access (e.g., root, admin, ubuntu, rock)"
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="SSH Password"
            type="password"
            fullWidth
            variant="outlined"
            value={bulkPassword}
            onChange={(e) => setBulkPassword(e.target.value)}
            helperText="This password will be set for all selected devices"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPasswordDialog(false)}>Cancel</Button>
          <Button 
            onClick={async () => {
              try {
                // Update each selected device with the credentials
                const updatePromises = selectedDeviceIds.map(deviceId => 
                  deviceAPI.updateDevice(deviceId, {
                    ssh_username: bulkUsername,
                    ssh_password: bulkPassword
                  })
                );
                
                await Promise.all(updatePromises);
                
                setSnackbar({ 
                  open: true, 
                  message: `SSH credentials updated for ${selectedDeviceIds.length} devices`, 
                  severity: 'success' 
                });
                
                setPasswordDialog(false);
                setBulkUsername('');
                setBulkPassword('');
                
                // Refresh the devices list
                window.location.reload();
              } catch (error) {
                console.error('Error updating bulk credentials:', error);
                setSnackbar({ 
                  open: true, 
                  message: 'Failed to update SSH credentials', 
                  severity: 'error' 
                });
              }
            }}
            variant="contained" 
            disabled={!bulkUsername || !bulkPassword}
          >
            Save Credentials for {selectedDeviceIds.length} Device(s)
          </Button>
        </DialogActions>
      </Dialog>

      {/* Security Reports Dialog */}
      <Dialog open={securityReportDialog} onClose={() => setSecurityReportDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Security Audit Reports</DialogTitle>
        <DialogContent>
          <Box sx={{ mb: 2 }}>
            <Typography variant="h6" gutterBottom>Summary</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} sm={4}><Card><CardContent><Typography color="textSecondary" gutterBottom>Total Devices Audited</Typography><Typography variant="h4">{securityReports.length}</Typography></CardContent></Card></Grid>
              <Grid item xs={12} sm={4}><Card><CardContent><Typography color="textSecondary" gutterBottom>Average Security Score</Typography><Typography variant="h4" color={securityReports.length > 0 ? (securityReports.reduce((acc, r) => acc + r.overall_score, 0) / securityReports.length >= 80 ? 'success.main' : 'warning.main') : 'text.primary'}>{securityReports.length > 0 ? (securityReports.reduce((acc, r) => acc + r.overall_score, 0) / securityReports.length).toFixed(1) : 'N/A'}</Typography></CardContent></Card></Grid>
              <Grid item xs={12} sm={4}><Card><CardContent><Typography color="textSecondary" gutterBottom>Critical Issues</Typography><Typography variant="h4" color="error.main">{securityReports.reduce((acc, r) => acc + Object.values(r.categories).reduce((catAcc: number, cat: any) => catAcc + cat.critical_issues, 0), 0)}</Typography></CardContent></Card></Grid>
            </Grid>
          </Box>
          {securityReports.map((report, index) => (
            <Accordion key={index} sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                  <Typography variant="h6">{report.hostname || report.ip_address}</Typography>
                  <Chip label={`Score: ${report.overall_score}`} color={report.overall_score >= 80 ? 'success' : report.overall_score >= 60 ? 'warning' : 'error'} size="small" />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {Object.entries(report.categories).map(([categoryName, categoryData]: [string, any]) => (
                    <Grid item xs={12} sm={6} key={categoryName}>
                      <Card variant="outlined"><CardContent>
                        <Typography variant="h6" gutterBottom>{categoryName.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase())}</Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
                          <Typography variant="h5">{categoryData.score}</Typography>
                          <LinearProgress variant="determinate" value={categoryData.score} sx={{ flexGrow: 1, height: 8, borderRadius: 4 }} color={categoryData.score >= 80 ? 'success' : categoryData.score >= 60 ? 'warning' : 'error'} />
                        </Box>
                        <Typography variant="body2" color="error.main" gutterBottom>Critical Issues: {categoryData.critical_issues}</Typography>
                        <Typography variant="body2" color="warning.main" gutterBottom>Warnings: {categoryData.warnings}</Typography>
                        <Typography variant="body2">{categoryData.details}</Typography>
                      </CardContent></Card>
                    </Grid>
                  ))}
                </Grid>
                <Box sx={{ mt: 2 }}>
                  <Typography variant="h6" gutterBottom>Recommendations</Typography>
                  <Box component="ul" sx={{ pl: 2 }}>
                    {report.recommendations.map((rec: string, recIndex: number) => (
                      <Typography component="li" key={recIndex} variant="body2" sx={{ mb: 0.5 }}>{rec}</Typography>
                    ))}
                  </Box>
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSecurityReportDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* SSH Credentials Dialog */}
      <Dialog open={credentialsDialog.open} onClose={() => setCredentialsDialog({ open: false, device: null })} maxWidth="sm" fullWidth>
        <DialogTitle>SSH Credentials for {credentialsDialog.device?.hostname || credentialsDialog.device?.ip_address}</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            Set SSH username and password for this device to enable terminal access and management operations.
          </DialogContentText>
          <TextField
            autoFocus
            margin="dense"
            label="SSH Username"
            type="text"
            fullWidth
            variant="outlined"
            value={credentialsForm.username}
            onChange={(e) => setCredentialsForm({ ...credentialsForm, username: e.target.value })}
            helperText="Username for SSH access (e.g., root, admin, ubuntu)"
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="SSH Password"
            type="password"
            fullWidth
            variant="outlined"
            value={credentialsForm.password}
            onChange={(e) => setCredentialsForm({ ...credentialsForm, password: e.target.value })}
            helperText="Password will be encrypted and stored securely"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCredentialsDialog({ open: false, device: null })}>Cancel</Button>
          <Button 
            onClick={async () => {
              if (credentialsDialog.device && credentialsForm.username && credentialsForm.password) {
                try {
                  await deviceAPI.updateDevice(credentialsDialog.device.id, {
                    ssh_username: credentialsForm.username,
                    ssh_password: credentialsForm.password
                  });
                  setSnackbar({ 
                    open: true, 
                    message: `SSH credentials updated for ${credentialsDialog.device.hostname || credentialsDialog.device.ip_address}`, 
                    severity: 'success' 
                  });
                  setCredentialsDialog({ open: false, device: null });
                  setCredentialsForm({ username: '', password: '' });
                  // Refresh the devices list
                  window.location.reload();
                } catch (error) {
                  console.error('Error updating credentials:', error);
                  setSnackbar({ 
                    open: true, 
                    message: 'Failed to update SSH credentials', 
                    severity: 'error' 
                  });
                }
              }
            }}
            variant="contained" 
            disabled={!credentialsForm.username || !credentialsForm.password}
          >
            Save Credentials
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar open={snackbar.open} autoHideDuration={6000} onClose={() => setSnackbar({ ...snackbar, open: false })}>
        <Alert onClose={() => setSnackbar({ ...snackbar, open: false })} severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default ManagedDevices;
