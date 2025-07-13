import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  TextField,
  InputAdornment,
  Button,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Snackbar,
  Tooltip,
  CircularProgress,
} from '@mui/material';
import {
  Search as SearchIcon,
  Visibility as VisibilityIcon,
  Refresh as RefreshIcon,
  MoreVert as MoreVertIcon,
  NetworkPing as PingIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkCheckIcon,
  Edit as EditIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { useNavigate } from 'react-router-dom';
import { deviceAPI } from '../services/api';

interface Device {
  id: number;
  ip_address: string;
  hostname: string;
  device_type: string;
  operating_system: string;
  status: string;
  last_seen: string;
  ai_risk_score: number;
  mac_address: string;
  open_ports?: string;
  vulnerabilities?: string;
}

interface DeviceAction {
  label: string;
  icon: React.ReactNode;
  action: (device: Device) => void;
  color?: 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success';
}

const DeviceList: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [actionDialog, setActionDialog] = useState<{ open: boolean; type: string; device: Device | null }>({
    open: false,
    type: '',
    device: null
  });
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>({
    open: false,
    message: '',
    severity: 'info'
  });
  
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: devicesData, refetch } = useQuery(
    'devices',
    async () => {
      const response = await deviceAPI.getDevices();
      return response.data;
    },
    { refetchInterval: 30000 }
  );

  // Mutations for device actions
  const pingMutation = useMutation(
    (deviceId: number) => deviceAPI.pingDevice(deviceId),
    {
      onSuccess: (data) => {
        showSnackbar(data.data.message, 'success');
        queryClient.invalidateQueries('devices');
      },
      onError: (error: any) => {
        showSnackbar(error.response?.data?.detail || 'Failed to ping device', 'error');
      }
    }
  );

  const portScanMutation = useMutation(
    (deviceId: number) => deviceAPI.scanDevicePorts(deviceId),
    {
      onSuccess: (data) => {
        showSnackbar(data.data.message, 'success');
        queryClient.invalidateQueries('devices');
      },
      onError: (error: any) => {
        showSnackbar(error.response?.data?.detail || 'Failed to scan ports', 'error');
      }
    }
  );

  const securityScanMutation = useMutation(
    (deviceId: number) => deviceAPI.securityScanDevice(deviceId),
    {
      onSuccess: (data) => {
        showSnackbar(data.data.message, 'success');
        queryClient.invalidateQueries('devices');
      },
      onError: (error: any) => {
        showSnackbar(error.response?.data?.detail || 'Failed to perform security scan', 'error');
      }
    }
  );

  const devices: Device[] = devicesData?.devices || [];

  const filteredDevices = devices.filter(device =>
    device.ip_address.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (device.hostname && device.hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
    device.device_type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'success';
      case 'offline':
        return 'error';
      case 'maintenance':
        return 'warning';
      default:
        return 'default';
    }
  };

  const getRiskColor = (score: number) => {
    if (score > 0.7) return 'error';
    if (score > 0.4) return 'warning';
    return 'success';
  };

  const handleViewDevice = (deviceId: number) => {
    navigate(`/devices/${deviceId}`);
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, device: Device) => {
    setAnchorEl(event.currentTarget);
    setSelectedDevice(device);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setSelectedDevice(null);
  };

  const handleAction = (action: (device: Device) => void) => {
    if (selectedDevice) {
      action(selectedDevice);
    }
    handleMenuClose();
  };

  const handlePing = (device: Device) => {
    pingMutation.mutate(device.id);
  };

  const handlePortScan = (device: Device) => {
    portScanMutation.mutate(device.id);
  };

  const handleSecurityScan = (device: Device) => {
    securityScanMutation.mutate(device.id);
  };

  const handleEdit = (device: Device) => {
    setActionDialog({ open: true, type: 'edit', device });
  };

  const handleViewDetails = (device: Device) => {
    setActionDialog({ open: true, type: 'details', device });
  };

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info') => {
    setSnackbar({ open: true, message, severity });
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const deviceActions: DeviceAction[] = [
    {
      label: 'View Details',
      icon: <InfoIcon />,
      action: handleViewDetails,
      color: 'primary'
    },
    {
      label: 'Ping Device',
      icon: <PingIcon />,
      action: handlePing,
      color: 'info'
    },
    {
      label: 'Scan Ports',
      icon: <NetworkCheckIcon />,
      action: handlePortScan,
      color: 'secondary'
    },
    {
      label: 'Security Scan',
      icon: <SecurityIcon />,
      action: handleSecurityScan,
      color: 'warning'
    },
    {
      label: 'Edit Device',
      icon: <EditIcon />,
      action: handleEdit,
      color: 'primary'
    }
  ];

  const getOpenPortsCount = (device: Device) => {
    if (!device.open_ports) return 0;
    try {
      const ports = JSON.parse(device.open_ports);
      return Array.isArray(ports) ? ports.length : 0;
    } catch {
      return 0;
    }
  };

  const getVulnerabilitiesCount = (device: Device) => {
    if (!device.vulnerabilities) return 0;
    try {
      const vulns = JSON.parse(device.vulnerabilities);
      return Array.isArray(vulns) ? vulns.length : 0;
    } catch {
      return 0;
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Network Devices
        </Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={() => refetch()}
        >
          Refresh
        </Button>
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <TextField
            fullWidth
            variant="outlined"
            placeholder="Search devices by IP, hostname, or type..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />
        </CardContent>
      </Card>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>IP Address</TableCell>
              <TableCell>Hostname</TableCell>
              <TableCell>Device Type</TableCell>
              <TableCell>Operating System</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Risk Score</TableCell>
              <TableCell>Open Ports</TableCell>
              <TableCell>Vulnerabilities</TableCell>
              <TableCell>Last Seen</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredDevices.map((device) => (
              <TableRow key={device.id} hover>
                <TableCell>
                  <Typography variant="body2" fontFamily="monospace">
                    {device.ip_address}
                  </Typography>
                </TableCell>
                <TableCell>
                  {device.hostname || 'Unknown'}
                </TableCell>
                <TableCell>
                  <Chip
                    label={device.device_type}
                    size="small"
                    variant="outlined"
                  />
                </TableCell>
                <TableCell>
                  {device.operating_system}
                </TableCell>
                <TableCell>
                  <Chip
                    label={device.status}
                    color={getStatusColor(device.status) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={`${(device.ai_risk_score * 100).toFixed(0)}%`}
                    color={getRiskColor(device.ai_risk_score) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={getOpenPortsCount(device)}
                    size="small"
                    variant="outlined"
                    color={getOpenPortsCount(device) > 0 ? 'warning' : 'default'}
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={getVulnerabilitiesCount(device)}
                    size="small"
                    variant="outlined"
                    color={getVulnerabilitiesCount(device) > 0 ? 'error' : 'default'}
                  />
                </TableCell>
                <TableCell>
                  {new Date(device.last_seen).toLocaleString()}
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Tooltip title="View Details">
                      <IconButton
                        size="small"
                        onClick={() => handleViewDevice(device.id)}
                        color="primary"
                      >
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="More Actions">
                      <IconButton
                        size="small"
                        onClick={(e) => handleMenuOpen(e, device)}
                        color="primary"
                      >
                        <MoreVertIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Actions Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
      >
        {deviceActions.map((action, index) => (
          <MenuItem
            key={index}
            onClick={() => handleAction(action.action)}
            disabled={
              (action.label === 'Ping Device' && pingMutation.isLoading) ||
              (action.label === 'Scan Ports' && portScanMutation.isLoading) ||
              (action.label === 'Security Scan' && securityScanMutation.isLoading)
            }
          >
            <ListItemIcon>
              {action.icon}
            </ListItemIcon>
            <ListItemText primary={action.label} />
            {(action.label === 'Ping Device' && pingMutation.isLoading) ||
             (action.label === 'Scan Ports' && portScanMutation.isLoading) ||
             (action.label === 'Security Scan' && securityScanMutation.isLoading) ? (
              <CircularProgress size={16} />
            ) : null}
          </MenuItem>
        ))}
      </Menu>

      {/* Action Results Dialog */}
      <Dialog
        open={actionDialog.open}
        onClose={() => setActionDialog({ open: false, type: '', device: null })}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {actionDialog.type === 'details' ? 'Device Details' : 'Edit Device'}
        </DialogTitle>
        <DialogContent>
          {actionDialog.device && actionDialog.type === 'details' && (
            <Box>
              <Typography variant="h6" gutterBottom>Device Information</Typography>
              <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2, mb: 2 }}>
                <Typography><strong>IP Address:</strong> {actionDialog.device.ip_address}</Typography>
                <Typography><strong>Hostname:</strong> {actionDialog.device.hostname || 'Unknown'}</Typography>
                <Typography><strong>Device Type:</strong> {actionDialog.device.device_type}</Typography>
                <Typography><strong>Operating System:</strong> {actionDialog.device.operating_system}</Typography>
                <Typography><strong>Status:</strong> {actionDialog.device.status}</Typography>
                <Typography><strong>Risk Score:</strong> {(actionDialog.device.ai_risk_score * 100).toFixed(1)}%</Typography>
              </Box>
              
              <Typography variant="h6" gutterBottom>Security Information</Typography>
              <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                <Typography><strong>Open Ports:</strong> {getOpenPortsCount(actionDialog.device)}</Typography>
                <Typography><strong>Vulnerabilities:</strong> {getVulnerabilitiesCount(actionDialog.device)}</Typography>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setActionDialog({ open: false, type: '', device: null })}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>

      {filteredDevices.length === 0 && (
        <Card sx={{ mt: 2 }}>
          <CardContent>
            <Typography variant="body1" textAlign="center" color="text.secondary">
              {searchTerm ? 'No devices found matching your search.' : 'No devices discovered yet. Start a network scan to discover devices.'}
            </Typography>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default DeviceList; 