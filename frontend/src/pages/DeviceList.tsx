import React, { useState, useEffect, useRef } from 'react';
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
  Checkbox,
  DialogContentText,
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
  Terminal as TerminalIcon,
  BuildCircle as BuildCircleIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { useNavigate } from 'react-router-dom';
import { deviceAPI } from '../services/api';
import XTermTerminal, {
  XTermTerminalHandle,
} from '../components/XTermTerminal';

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
  ssh_username?: string;
  ssh_password?: string;
  is_managed?: boolean;
}

interface DeviceAction {
  label: string;
  icon: React.ReactNode;
  action: (device: Device) => void;
  color?: 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success';
}

const TERMINAL_STATES = {
  IDLE: 'idle',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  ERROR: 'error',
  DISCONNECTED: 'disconnected',
};

const DeviceList: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState<
    | 'ip_address'
    | 'hostname'
    | 'device_type'
    | 'operating_system'
    | 'ai_risk_score'
    | 'last_seen'
  >('ip_address');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [menuDevice, setMenuDevice] = useState<Device | null>(null);
  const [osFilter, setOsFilter] = useState<string>('all');
  const [ipStart, setIpStart] = useState('');
  const [ipEnd, setIpEnd] = useState('');
  const [actionDialog, setActionDialog] = useState<{
    open: boolean;
    type: string;
    device: Device | null;
  }>({
    open: false,
    type: '',
    device: null,
  });
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info';
  }>({
    open: false,
    message: '',
    severity: 'info',
  });
  const [shellDialog, setShellDialog] = useState<{
    open: boolean;
    device: Device | null;
  }>({ open: false, device: null });
  const [aiPatchLoading, setAiPatchLoading] = useState(false);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<number[]>([]);
  const [bulkSshDialog, setBulkSshDialog] = useState(false);
  const [bulkSshUsername, setBulkSshUsername] = useState('');
  const [bulkSshPassword, setBulkSshPassword] = useState('');
  const [bulkSaving, setBulkSaving] = useState(false);
  const [editSshUsername, setEditSshUsername] = useState('');
  const [editSshPassword, setEditSshPassword] = useState('');
  const [editSaving, setEditSaving] = useState(false);
  const [terminalState, setTerminalState] = useState(TERMINAL_STATES.IDLE);
  const [terminalError, setTerminalError] = useState<string | null>(null);
  const [terminalInitFailed, setTerminalInitFailed] = useState(false);

  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const terminalRef = useRef<XTermTerminalHandle>(null);

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
        showSnackbar(
          error.response?.data?.detail || 'Failed to ping device',
          'error'
        );
      },
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
        showSnackbar(
          error.response?.data?.detail || 'Failed to scan ports',
          'error'
        );
      },
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
        showSnackbar(
          error.response?.data?.detail || 'Failed to perform security scan',
          'error'
        );
      },
    }
  );

  const markManagedMutation = useMutation(
    (deviceIds: number[]) => deviceAPI.markDevicesAsManaged(deviceIds),
    {
      onSuccess: (data) => {
        showSnackbar(data.data.message, 'success');
        setSelectedDeviceIds([]);
        queryClient.invalidateQueries('devices');
        queryClient.invalidateQueries('managed-devices');
      },
      onError: (error: any) => {
        showSnackbar(
          error.response?.data?.detail || 'Failed to mark devices as managed',
          'error'
        );
      },
    }
  );

  const devices: Device[] = devicesData?.devices || [];

  // Helper to compare IPs as numbers
  const ipToNumber = (ip: string) =>
    ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);

  // Filtering
  const filteredDevices = devices.filter((device) => {
    // Search term
    const matchesSearch =
      device.ip_address.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (device.hostname &&
        device.hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
      device.device_type.toLowerCase().includes(searchTerm.toLowerCase());
    // OS filter
    const matchesOs =
      osFilter === 'all' || device.operating_system === osFilter;
    // IP range filter
    let matchesIpRange = true;
    if (ipStart && ipEnd) {
      try {
        const ipNum = ipToNumber(device.ip_address);
        matchesIpRange =
          ipToNumber(ipStart) <= ipNum && ipNum <= ipToNumber(ipEnd);
      } catch {
        matchesIpRange = true;
      }
    }
    return matchesSearch && matchesOs && matchesIpRange;
  });

  // Sorting
  const sortedDevices = [...filteredDevices].sort((a, b) => {
    let aValue: any = a[sortField] ?? '';
    let bValue: any = b[sortField] ?? '';
    if (sortField === 'ai_risk_score') {
      aValue = Number(aValue);
      bValue = Number(bValue);
    } else if (sortField === 'last_seen') {
      aValue = new Date(aValue).getTime();
      bValue = new Date(bValue).getTime();
    } else if (sortField === 'operating_system') {
      aValue = aValue.toString().toLowerCase();
      bValue = bValue.toString().toLowerCase();
    } else {
      aValue = aValue.toString().toLowerCase();
      bValue = bValue.toString().toLowerCase();
    }
    if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
    if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
    return 0;
  });

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

  const handleAction = (action: (device: Device) => void) => {
    if (selectedDevice) {
      action(selectedDevice);
    }
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

  const handleMenuOpen = (
    event: React.MouseEvent<HTMLElement>,
    device: Device
  ) => {
    setAnchorEl(event.currentTarget);
    setMenuDevice(device);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setMenuDevice(null);
  };

  const showSnackbar = (
    message: string,
    severity: 'success' | 'error' | 'info'
  ) => {
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
      color: 'primary',
    },
    {
      label: 'Ping Device',
      icon: <PingIcon />,
      action: handlePing,
      color: 'info',
    },
    {
      label: 'Scan Ports',
      icon: <NetworkCheckIcon />,
      action: handlePortScan,
      color: 'secondary',
    },
    {
      label: 'Security Scan',
      icon: <SecurityIcon />,
      action: handleSecurityScan,
      color: 'warning',
    },
    {
      label: 'Edit Device',
      icon: <EditIcon />,
      action: handleEdit,
      color: 'primary',
    },
    {
      label: 'Shell',
      icon: <TerminalIcon />,
      action: (device: Device) => setShellDialog({ open: true, device }),
      color: 'primary',
    },
    {
      label: 'AI Automated OS & Security Patches',
      icon: <BuildCircleIcon />,
      action: async (device: Device) => {
        setAiPatchLoading(true);
        try {
          const res = await deviceAPI.aiPatchDevice(device.id);
          showSnackbar(res.data.message, 'success');
        } catch (e: any) {
          showSnackbar(
            e?.response?.data?.detail || 'Failed to trigger AI patching',
            'error'
          );
        } finally {
          setAiPatchLoading(false);
        }
      },
      color: 'secondary',
    },
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

  // Get unique OS options
  const osOptions = Array.from(
    new Set(devices.map((d) => d.operating_system).filter(Boolean))
  );

  // When opening Edit Device dialog, prefill SSH fields
  useEffect(() => {
    if (
      actionDialog.open &&
      actionDialog.type === 'edit' &&
      actionDialog.device
    ) {
      setEditSshUsername(actionDialog.device.ssh_username || '');
      setEditSshPassword(actionDialog.device.ssh_password ? '********' : '');
    }
  }, [actionDialog]);

  // Handle checkbox select
  const handleSelectDevice = (id: number) => {
    setSelectedDeviceIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };
  const handleSelectAll = (checked: boolean) => {
    setSelectedDeviceIds(checked ? devices.map((d) => d.id) : []);
  };

  // Bulk SSH credential save
  const handleBulkSshSave = async () => {
    setBulkSaving(true);
    try {
      await Promise.all(
        selectedDeviceIds.map((id) =>
          deviceAPI.updateDevice(id, {
            ssh_username: bulkSshUsername,
            ssh_password: bulkSshPassword,
          })
        )
      );
      setSnackbar({
        open: true,
        message: 'SSH credentials updated for selected devices!',
        severity: 'success',
      });
      setBulkSshDialog(false);
      setBulkSshUsername('');
      setBulkSshPassword('');
      setSelectedDeviceIds([]);
      refetch();
    } catch {
      setSnackbar({
        open: true,
        message: 'Failed to update SSH credentials.',
        severity: 'error',
      });
    } finally {
      setBulkSaving(false);
    }
  };

  // Edit Device SSH credential save
  const handleEditSshSave = async () => {
    if (!actionDialog.device) return;
    setEditSaving(true);
    try {
      const updateData: any = { ssh_username: editSshUsername };
      // Only send password if changed from masked value
      if (editSshPassword && editSshPassword !== '********') {
        updateData.ssh_password = editSshPassword;
      }
      await deviceAPI.updateDevice(actionDialog.device.id, updateData);
      setSnackbar({
        open: true,
        message: 'SSH credentials updated!',
        severity: 'success',
      });
      setActionDialog({ ...actionDialog, open: false });
      refetch();
    } catch {
      setSnackbar({
        open: true,
        message: 'Failed to update SSH credentials.',
        severity: 'error',
      });
    } finally {
      setEditSaving(false);
    }
  };

  return (
    <Box>
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          mb: 3,
        }}
      >
        <Typography variant="h4" component="h1">
          Discovered Devices
        </Typography>
        <Typography variant="body2" color="textSecondary" sx={{ mt: 1, mb: 2 }}>
          Devices detected on the network that are not yet managed. Use "Mark as
          Managed" to move devices to the Managed Devices page.
        </Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={() => refetch()}
        >
          Refresh
        </Button>
      </Box>

      {/* Selected Machine for Monitoring */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h5" gutterBottom>
            Selected Machine for Monitoring
          </Typography>
          {selectedDevice ? (
            <Box>
              <Typography variant="subtitle1">
                {selectedDevice.hostname || selectedDevice.ip_address}
              </Typography>
              <Typography variant="body2">
                IP: {selectedDevice.ip_address}
              </Typography>
              <Typography variant="body2">
                Type: {selectedDevice.device_type}
              </Typography>
              <Typography variant="body2">
                OS: {selectedDevice.operating_system}
              </Typography>
              <Button
                variant="outlined"
                color="secondary"
                sx={{ mt: 1 }}
                onClick={() => setSelectedDevice(null)}
              >
                Unselect
              </Button>
            </Box>
          ) : (
            <Typography color="text.secondary">
              No machine selected for monitoring.
            </Typography>
          )}
        </CardContent>
      </Card>

      {/* Available Devices Section */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Button
              variant="contained"
              color="secondary"
              disabled={selectedDeviceIds.length === 0}
              onClick={() => setBulkSshDialog(true)}
              sx={{ mr: 2 }}
            >
              Set SSH Credentials for Selected
            </Button>
            <Button
              variant="contained"
              color="primary"
              disabled={selectedDeviceIds.length === 0}
              onClick={() => markManagedMutation.mutate(selectedDeviceIds)}
              sx={{ mr: 2 }}
            >
              Mark as Managed ({selectedDeviceIds.length})
            </Button>
            <Typography variant="h5">Available Devices</Typography>
            <TextField
              size="small"
              variant="outlined"
              placeholder="Quick filter..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              sx={{ minWidth: 200 }}
            />
            <TextField
              select
              size="small"
              label="OS"
              value={osFilter}
              onChange={(e) => setOsFilter(e.target.value)}
              sx={{ minWidth: 120 }}
            >
              <MenuItem value="all">All OS</MenuItem>
              {osOptions.map((os) => (
                <MenuItem key={os} value={os}>
                  {os}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              size="small"
              label="Start IP"
              value={ipStart}
              onChange={(e) => setIpStart(e.target.value)}
              placeholder="192.168.1.1"
              sx={{ minWidth: 130 }}
            />
            <TextField
              size="small"
              label="End IP"
              value={ipEnd}
              onChange={(e) => setIpEnd(e.target.value)}
              placeholder="192.168.1.254"
              sx={{ minWidth: 130 }}
            />
            <TextField
              select
              size="small"
              label="Sort by"
              value={sortField}
              onChange={(e) => setSortField(e.target.value as any)}
              sx={{ minWidth: 120 }}
            >
              <MenuItem value="ip_address">IP Address</MenuItem>
              <MenuItem value="hostname">Hostname</MenuItem>
              <MenuItem value="device_type">Type</MenuItem>
              <MenuItem value="operating_system">Operating System</MenuItem>
              <MenuItem value="ai_risk_score">Risk Score</MenuItem>
              <MenuItem value="last_seen">Last Seen</MenuItem>
            </TextField>
            <Button
              size="small"
              variant="outlined"
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
            >
              {sortOrder === 'asc' ? 'Asc' : 'Desc'}
            </Button>
          </Box>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell padding="checkbox">
                    <Checkbox
                      checked={
                        selectedDeviceIds.length === devices.length &&
                        devices.length > 0
                      }
                      indeterminate={
                        selectedDeviceIds.length > 0 &&
                        selectedDeviceIds.length < devices.length
                      }
                      onChange={(e) => handleSelectAll(e.target.checked)}
                    />
                  </TableCell>
                  <TableCell>IP Address</TableCell>
                  <TableCell>Hostname</TableCell>
                  <TableCell>Device Type</TableCell>
                  <TableCell>Operating System</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Risk Score</TableCell>
                  <TableCell>Last Seen</TableCell>
                  <TableCell>Monitor</TableCell>
                  <TableCell>Preview</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedDevices.map((device) => (
                  <TableRow
                    key={device.id}
                    sx={{
                      transition:
                        'background 0.2s, box-shadow 0.2s, transform 0.15s',
                      cursor: 'pointer',
                      '&:hover, &:focus': {
                        backgroundColor: 'rgba(0, 212, 170, 0.08)',
                        boxShadow: 3,
                        transform: 'scale(1.01)',
                      },
                    }}
                  >
                    <TableCell padding="checkbox">
                      <Checkbox
                        checked={selectedDeviceIds.includes(device.id)}
                        onChange={() => handleSelectDevice(device.id)}
                      />
                    </TableCell>
                    <TableCell>{device.ip_address}</TableCell>
                    <TableCell>{device.hostname || 'Unknown'}</TableCell>
                    <TableCell>{device.device_type}</TableCell>
                    <TableCell>{device.operating_system}</TableCell>
                    <TableCell>{device.status}</TableCell>
                    <TableCell>
                      {(device.ai_risk_score * 100).toFixed(0)}%
                    </TableCell>
                    <TableCell>
                      {new Date(device.last_seen).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Button
                        size="small"
                        variant={
                          selectedDevice?.id === device.id
                            ? 'contained'
                            : 'outlined'
                        }
                        color="primary"
                        onClick={() => setSelectedDevice(device)}
                        disabled={selectedDevice?.id === device.id}
                      >
                        {selectedDevice?.id === device.id
                          ? 'Monitoring'
                          : 'Monitor'}
                      </Button>
                    </TableCell>
                    <TableCell>
                      <Tooltip title="View Details">
                        <IconButton
                          size="small"
                          onClick={() => handleViewDetails(device)}
                          color="primary"
                        >
                          <VisibilityIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Tooltip title="More Actions">
                        <IconButton
                          size="small"
                          onClick={(e) => handleMenuOpen(e, device)}
                          color="primary"
                        >
                          <MoreVertIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
      {/* Actions Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        {deviceActions.map((action, index) => (
          <MenuItem
            key={index}
            onClick={() => {
              if (menuDevice) action.action(menuDevice);
              handleMenuClose();
            }}
            disabled={
              (action.label === 'Ping Device' && pingMutation.isLoading) ||
              (action.label === 'Scan Ports' && portScanMutation.isLoading) ||
              (action.label === 'Security Scan' &&
                securityScanMutation.isLoading) ||
              (action.label === 'Shell' && false) || // Shell is handled by a separate dialog
              (action.label === 'AI Automated OS & Security Patches' &&
                aiPatchLoading)
            }
          >
            <ListItemIcon>{action.icon}</ListItemIcon>
            <ListItemText primary={action.label} />
            {(action.label === 'Ping Device' && pingMutation.isLoading) ||
            (action.label === 'Scan Ports' && portScanMutation.isLoading) ||
            (action.label === 'Security Scan' &&
              securityScanMutation.isLoading) ||
            (action.label === 'Shell' && false) || // Shell is handled by a separate dialog
            (action.label === 'AI Automated OS & Security Patches' &&
              aiPatchLoading) ? (
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
              <Typography variant="h6" gutterBottom>
                Device Information
              </Typography>
              <Box
                sx={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr',
                  gap: 2,
                  mb: 2,
                }}
              >
                <Typography>
                  <strong>IP Address:</strong> {actionDialog.device.ip_address}
                </Typography>
                <Typography>
                  <strong>Hostname:</strong>{' '}
                  {actionDialog.device.hostname || 'Unknown'}
                </Typography>
                <Typography>
                  <strong>Device Type:</strong>{' '}
                  {actionDialog.device.device_type}
                </Typography>
                <Typography>
                  <strong>Operating System:</strong>{' '}
                  {actionDialog.device.operating_system}
                </Typography>
                <Typography>
                  <strong>Status:</strong> {actionDialog.device.status}
                </Typography>
                <Typography>
                  <strong>Risk Score:</strong>{' '}
                  {(actionDialog.device.ai_risk_score * 100).toFixed(1)}%
                </Typography>
              </Box>

              <Typography variant="h6" gutterBottom>
                Security Information
              </Typography>
              <Box
                sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}
              >
                <Box>
                  <Typography>
                    <strong>Open Ports:</strong>
                  </Typography>
                  {(() => {
                    let ports: {
                      port: number;
                      service: string;
                      banner: string;
                    }[] = [];
                    try {
                      ports = actionDialog.device.open_ports
                        ? JSON.parse(actionDialog.device.open_ports)
                        : [];
                    } catch {}
                    return ports.length > 0 ? (
                      <Table size="small" sx={{ mt: 1 }}>
                        <TableHead>
                          <TableRow>
                            <TableCell>Port</TableCell>
                            <TableCell>Service</TableCell>
                            <TableCell>Banner</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {ports.map((p, idx) => (
                            <TableRow key={idx}>
                              <TableCell>{p.port}</TableCell>
                              <TableCell>{p.service}</TableCell>
                              <TableCell
                                style={{
                                  maxWidth: 200,
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                }}
                              >
                                {p.banner || '-'}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    ) : (
                      <Typography color="text.secondary">None</Typography>
                    );
                  })()}
                </Box>
                <Box>
                  <Typography>
                    <strong>Vulnerabilities:</strong>
                  </Typography>
                  {(() => {
                    let vulns: any[] = [];
                    try {
                      vulns = actionDialog.device.vulnerabilities
                        ? JSON.parse(actionDialog.device.vulnerabilities)
                        : [];
                    } catch {}
                    return vulns.length > 0 ? (
                      <Table size="small" sx={{ mt: 1 }}>
                        <TableHead>
                          <TableRow>
                            <TableCell>ID</TableCell>
                            <TableCell>Severity</TableCell>
                            <TableCell>Description</TableCell>
                            <TableCell>Port</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {vulns.map((vuln, idx) => (
                            <TableRow key={idx}>
                              <TableCell>{vuln.id || '-'}</TableCell>
                              <TableCell>{vuln.severity || '-'}</TableCell>
                              <TableCell>{vuln.description || '-'}</TableCell>
                              <TableCell>
                                {vuln.port != null ? vuln.port : '-'}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    ) : (
                      <Typography color="text.secondary">None</Typography>
                    );
                  })()}
                </Box>
              </Box>
            </Box>
          )}
          {actionDialog.type === 'edit' && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle1" sx={{ mb: 1 }}>
                SSH Credentials
              </Typography>
              <TextField
                label="SSH Username"
                value={editSshUsername}
                onChange={(e) => setEditSshUsername(e.target.value)}
                sx={{ mb: 2, mr: 2 }}
              />
              <TextField
                label="SSH Password"
                type="password"
                value={editSshPassword}
                onChange={(e) => setEditSshPassword(e.target.value)}
                sx={{ mb: 2 }}
                placeholder={
                  actionDialog.device?.ssh_password ? '********' : ''
                }
              />
              <Button
                variant="contained"
                color="primary"
                onClick={handleEditSshSave}
                disabled={editSaving}
                sx={{ ml: 2 }}
              >
                {editSaving ? 'Saving...' : 'Save SSH Credentials'}
              </Button>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() =>
              setActionDialog({ open: false, type: '', device: null })
            }
          >
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Shell Dialog */}
      <Dialog
        open={shellDialog.open}
        onClose={() => {
          // Disconnect terminal before closing dialog
          terminalRef.current?.disconnect();
          setShellDialog({ open: false, device: null });
        }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Remote Shell -{' '}
          {shellDialog.device?.hostname || shellDialog.device?.ip_address}
        </DialogTitle>
        <DialogContent style={{ display: 'flex', minHeight: 400 }}>
          {/* Sidebar for quick commands and automations */}
          <Box
            sx={{
              width: 200,
              pr: 2,
              borderRight: '1px solid #eee',
              display: 'flex',
              flexDirection: 'column',
              gap: 1,
            }}
          >
            <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
              🚀 System Automation
            </Typography>
            <Button
              size="small"
              variant="contained"
              color="primary"
              onClick={() => {
                terminalRef.current?.write(
                  'chmod +x /tmp/edu_admin/system_update.sh && /tmp/edu_admin/system_update.sh\r'
                );
              }}
              sx={{ mb: 1 }}
            >
              🔄 System Update
            </Button>

            <Button
              size="small"
              variant="contained"
              color="warning"
              onClick={() => {
                terminalRef.current?.write(
                  'chmod +x /tmp/edu_admin/security_audit.sh && /tmp/edu_admin/security_audit.sh\r'
                );
              }}
              sx={{ mb: 1 }}
            >
              🔒 Security Audit
            </Button>

            <Button
              size="small"
              variant="contained"
              color="info"
              onClick={() => {
                terminalRef.current?.write(
                  'chmod +x /tmp/edu_admin/ansible_setup.sh && /tmp/edu_admin/ansible_setup.sh setup\r'
                );
              }}
              sx={{ mb: 1 }}
            >
              ⚙️ Ansible Setup
            </Button>

            <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
              ☸️ Kubernetes
            </Typography>
            <Button
              size="small"
              variant="contained"
              color="secondary"
              onClick={() => {
                terminalRef.current?.write(
                  'chmod +x /tmp/edu_admin/k8s_context.sh && /tmp/edu_admin/k8s_context.sh current\r'
                );
              }}
              sx={{ mb: 1 }}
            >
              📋 K8s Context
            </Button>

            <Button
              size="small"
              variant="outlined"
              color="secondary"
              onClick={() => {
                terminalRef.current?.write(
                  'chmod +x /tmp/edu_admin/k8s_context.sh && /tmp/edu_admin/k8s_context.sh contexts\r'
                );
              }}
              sx={{ mb: 1 }}
            >
              🔄 Switch Context
            </Button>

            <Button
              size="small"
              variant="contained"
              color="primary"
              onClick={() => {
                terminalRef.current?.write(
                  'chmod +x /tmp/edu_admin/docker_install_rock5b.sh && /tmp/edu_admin/docker_install_rock5b.sh\r'
                );
              }}
              sx={{ mb: 1 }}
            >
              🐋 Install Docker
            </Button>

            <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
              🔧 Advanced
            </Typography>
            <Button
              size="small"
              variant="outlined"
              color="error"
              onClick={() => {
                terminalRef.current?.write('sudo tcpdump -i any -c 50\r');
              }}
              sx={{ mb: 1 }}
            >
              📊 Network Capture
            </Button>

            <Button
              size="small"
              variant="outlined"
              color="warning"
              onClick={() => {
                terminalRef.current?.write(
                  'sudo netstat -tuln | grep LISTEN\r'
                );
              }}
              sx={{ mb: 1 }}
            >
              🔌 Open Ports
            </Button>
          </Box>
          {/* Terminal Area */}
          <Box sx={{ flexGrow: 1, pl: 2, minWidth: 0, position: 'relative' }}>
            {shellDialog.device && (
              <XTermTerminal
                ref={terminalRef}
                wsUrl={`${
                  window.location.protocol === 'https:' ? 'wss' : 'ws'
                }://${window.location.hostname}:8001/api/devices/${
                  shellDialog.device.id
                }/shell`}
                height={350}
                fontSize={14}
              />
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              // Disconnect terminal before closing dialog
              terminalRef.current?.disconnect();
              setShellDialog({ open: false, device: null });
            }}
          >
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
            <Typography
              variant="body1"
              textAlign="center"
              color="text.secondary"
            >
              {searchTerm
                ? 'No devices found matching your search.'
                : 'No devices discovered yet. Start a network scan to discover devices.'}
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Bulk SSH credentials dialog: */}
      <Dialog open={bulkSshDialog} onClose={() => setBulkSshDialog(false)}>
        <DialogTitle>Set SSH Credentials for Selected Devices</DialogTitle>
        <DialogContent>
          <DialogContentText>
            This will update SSH credentials for {selectedDeviceIds.length}{' '}
            selected devices.
          </DialogContentText>
          <TextField
            label="SSH Username"
            value={bulkSshUsername}
            onChange={(e) => setBulkSshUsername(e.target.value)}
            sx={{ mb: 2, mt: 2, mr: 2 }}
          />
          <TextField
            label="SSH Password"
            type="password"
            value={bulkSshPassword}
            onChange={(e) => setBulkSshPassword(e.target.value)}
            sx={{ mb: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBulkSshDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleBulkSshSave}
            disabled={bulkSaving}
          >
            {bulkSaving ? 'Saving...' : 'Save SSH Credentials'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DeviceList;
