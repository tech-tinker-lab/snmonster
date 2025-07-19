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
  TextField,
  InputAdornment,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Snackbar,
  CircularProgress,
  Checkbox,
  DialogContentText,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  RemoveCircle as RemoveFromManagedIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  MoreVert as MoreVertIcon,
  VpnKey as PasswordIcon,
  Storage as DockerIcon,
  Security as SecurityIcon,
  Assessment as ReportIcon,
  CloudDownload as InstallIcon,
  ExpandMore as ExpandMoreIcon,
  Build as AnsibleIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from 'react-query';
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
  ssh_username?: string;
  ssh_password?: string;
  is_managed: boolean;
}

const ManagedDevices: React.FC = () => {
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
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<number[]>([]);
  const [removeDialog, setRemoveDialog] = useState(false);
  const [bulkActionsAnchor, setBulkActionsAnchor] =
    useState<null | HTMLElement>(null);
  const [passwordDialog, setPasswordDialog] = useState(false);
  const [bulkPassword, setBulkPassword] = useState('');
  const [securityReportDialog, setSecurityReportDialog] = useState(false);
  const [securityReports, setSecurityReports] = useState<any[]>([]);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info';
  }>({
    open: false,
    message: '',
    severity: 'info',
  });

  const queryClient = useQueryClient();

  const {
    data: devicesData,
    refetch,
    isLoading,
  } = useQuery(
    'managed-devices',
    async () => {
      const response = await deviceAPI.getManagedDevices();
      return response.data;
    },
    { refetchInterval: 30000 }
  );

  const unmarkManagedMutation = useMutation(
    async (deviceIds: number[]) => {
      const response = await deviceAPI.unmarkDevicesAsManaged(deviceIds);
      return response.data;
    },
    {
      onSuccess: (data) => {
        setSnackbar({
          open: true,
          message: data.message,
          severity: 'success',
        });
        setSelectedDeviceIds([]);
        setRemoveDialog(false);
        queryClient.invalidateQueries('managed-devices');
        queryClient.invalidateQueries('devices'); // Refresh the main devices list too
      },
      onError: (error: any) => {
        setSnackbar({
          open: true,
          message:
            error.response?.data?.detail ||
            'Failed to remove devices from management',
          severity: 'error',
        });
      },
    }
  );

  const setBulkPasswordMutation = useMutation(
    async ({
      deviceIds,
      password,
    }: {
      deviceIds: number[];
      password: string;
    }) => {
      const response = await deviceAPI.setBulkPassword(deviceIds, password);
      return response.data;
    },
    {
      onSuccess: (data) => {
        setSnackbar({
          open: true,
          message: data.message,
          severity: 'success',
        });
        setPasswordDialog(false);
        setBulkPassword('');
        setBulkActionsAnchor(null);
        queryClient.invalidateQueries('managed-devices');
      },
      onError: (error: any) => {
        setSnackbar({
          open: true,
          message: error.response?.data?.detail || 'Failed to set passwords',
          severity: 'error',
        });
      },
    }
  );

  const installDockerMutation = useMutation(
    async (deviceIds: number[]) => {
      setActionInProgress('Installing Docker...');
      const response = await deviceAPI.installDocker(deviceIds);
      return response.data;
    },
    {
      onSuccess: (data) => {
        setActionInProgress(null);
        setSnackbar({
          open: true,
          message: data.message,
          severity: 'success',
        });
        setBulkActionsAnchor(null);
      },
      onError: (error: any) => {
        setActionInProgress(null);
        setSnackbar({
          open: true,
          message: error.response?.data?.detail || 'Failed to install Docker',
          severity: 'error',
        });
      },
    }
  );

  const installAnsibleMutation = useMutation(
    async (deviceIds: number[]) => {
      setActionInProgress('Installing Ansible...');
      const response = await deviceAPI.installAnsible(deviceIds);
      return response.data;
    },
    {
      onSuccess: (data) => {
        setActionInProgress(null);
        setSnackbar({
          open: true,
          message: data.message,
          severity: 'success',
        });
        setBulkActionsAnchor(null);
      },
      onError: (error: any) => {
        setActionInProgress(null);
        setSnackbar({
          open: true,
          message: error.response?.data?.detail || 'Failed to install Ansible',
          severity: 'error',
        });
      },
    }
  );

  const runSecurityAuditMutation = useMutation(
    async (deviceIds: number[]) => {
      setActionInProgress('Running Security Audit...');
      const response = await deviceAPI.runSecurityAudit(deviceIds);
      return response.data;
    },
    {
      onSuccess: (data) => {
        setActionInProgress(null);
        setSnackbar({
          open: true,
          message: data.message,
          severity: 'success',
        });
        setBulkActionsAnchor(null);
        // Automatically fetch reports after audit
        fetchSecurityReports();
      },
      onError: (error: any) => {
        setActionInProgress(null);
        setSnackbar({
          open: true,
          message:
            error.response?.data?.detail || 'Failed to run security audit',
          severity: 'error',
        });
      },
    }
  );

  const fetchSecurityReports = async () => {
    try {
      const response = await deviceAPI.getSecurityReports(selectedDeviceIds);
      setSecurityReports(response.data.reports);
      setSecurityReportDialog(true);
    } catch (error: any) {
      setSnackbar({
        open: true,
        message:
          error.response?.data?.detail || 'Failed to fetch security reports',
        severity: 'error',
      });
    }
  };

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
      aValue = new Date(aValue).getTime();
      bValue = new Date(bValue).getTime();
    }

    if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
    if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
    return 0;
  });

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const handleSelectDevice = (deviceId: number) => {
    setSelectedDeviceIds((prev) =>
      prev.includes(deviceId)
        ? prev.filter((id) => id !== deviceId)
        : [...prev, deviceId]
    );
  };

  const handleSelectAll = () => {
    if (selectedDeviceIds.length === sortedDevices.length) {
      setSelectedDeviceIds([]);
    } else {
      setSelectedDeviceIds(sortedDevices.map((device) => device.id));
    }
  };

  const handleRemoveFromManaged = () => {
    if (selectedDeviceIds.length > 0) {
      unmarkManagedMutation.mutate(selectedDeviceIds);
    }
  };

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
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box
        sx={{
          mb: 3,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Typography
          variant="h4"
          component="h1"
          sx={{ fontWeight: 'bold', color: 'primary.main' }}
        >
          Managed Devices
        </Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={() => refetch()}
          disabled={isLoading}
        >
          Refresh
        </Button>
      </Box>

      {/* Stats Cards */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: 2,
          mb: 3,
        }}
      >
        <Card>
          <CardContent>
            <Typography color="textSecondary" gutterBottom>
              Total Managed Devices
            </Typography>
            <Typography variant="h5" component="div">
              {devices.length}
            </Typography>
          </CardContent>
        </Card>
        <Card>
          <CardContent>
            <Typography color="textSecondary" gutterBottom>
              Online Devices
            </Typography>
            <Typography variant="h5" component="div" color="success.main">
              {
                devices.filter(
                  (d: Device) => d.status.toLowerCase() === 'online'
                ).length
              }
            </Typography>
          </CardContent>
        </Card>
        <Card>
          <CardContent>
            <Typography color="textSecondary" gutterBottom>
              High Risk Devices
            </Typography>
            <Typography variant="h5" component="div" color="error.main">
              {devices.filter((d: Device) => d.ai_risk_score >= 8).length}
            </Typography>
          </CardContent>
        </Card>
        <Card>
          <CardContent>
            <Typography color="textSecondary" gutterBottom>
              Selected Devices
            </Typography>
            <Typography variant="h5" component="div" color="primary.main">
              {selectedDeviceIds.length}
            </Typography>
          </CardContent>
        </Card>
      </Box>

      {/* Controls */}
      <Box
        sx={{
          mb: 3,
          display: 'flex',
          gap: 2,
          alignItems: 'center',
          flexWrap: 'wrap',
        }}
      >
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
        <Button
          variant="contained"
          color="primary"
          startIcon={<MoreVertIcon />}
          disabled={selectedDeviceIds.length === 0}
          onClick={(e) => setBulkActionsAnchor(e.currentTarget)}
        >
          Bulk Actions ({selectedDeviceIds.length})
        </Button>
        <Button
          variant="contained"
          color="warning"
          startIcon={<RemoveFromManagedIcon />}
          disabled={selectedDeviceIds.length === 0}
          onClick={() => setRemoveDialog(true)}
        >
          Remove from Management ({selectedDeviceIds.length})
        </Button>
        <Button
          variant="outlined"
          startIcon={<ReportIcon />}
          disabled={selectedDeviceIds.length === 0}
          onClick={fetchSecurityReports}
        >
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
      <Menu
        anchorEl={bulkActionsAnchor}
        open={Boolean(bulkActionsAnchor)}
        onClose={() => setBulkActionsAnchor(null)}
      >
        <MenuItem
          onClick={() => {
            setPasswordDialog(true);
            setBulkActionsAnchor(null);
          }}
        >
          <ListItemIcon>
            <PasswordIcon />
          </ListItemIcon>
          <ListItemText primary="Set SSH Password" />
        </MenuItem>
        <Divider />
        <MenuItem
          onClick={() => installDockerMutation.mutate(selectedDeviceIds)}
        >
          <ListItemIcon>
            <DockerIcon />
          </ListItemIcon>
          <ListItemText primary="Install Docker" />
        </MenuItem>
        <MenuItem
          onClick={() => installAnsibleMutation.mutate(selectedDeviceIds)}
        >
          <ListItemIcon>
            <AnsibleIcon />
          </ListItemIcon>
          <ListItemText primary="Install Ansible" />
        </MenuItem>
        <Divider />
        <MenuItem
          onClick={() => runSecurityAuditMutation.mutate(selectedDeviceIds)}
        >
          <ListItemIcon>
            <SecurityIcon />
          </ListItemIcon>
          <ListItemText primary="Run Security Audit" />
        </MenuItem>
      </Menu>

      {/* Devices Table */}
      <Card>
        <CardContent>
          {isLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
              <CircularProgress />
            </Box>
          ) : (
            <TableContainer component={Paper} sx={{ maxHeight: 600 }}>
              <Table stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell padding="checkbox">
                      <Checkbox
                        checked={
                          selectedDeviceIds.length === sortedDevices.length &&
                          sortedDevices.length > 0
                        }
                        indeterminate={
                          selectedDeviceIds.length > 0 &&
                          selectedDeviceIds.length < sortedDevices.length
                        }
                        onChange={handleSelectAll}
                      />
                    </TableCell>
                    <TableCell
                      sx={{ cursor: 'pointer', fontWeight: 'bold' }}
                      onClick={() => handleSort('ip_address')}
                    >
                      IP Address{' '}
                      {sortField === 'ip_address' &&
                        (sortOrder === 'asc' ? '↑' : '↓')}
                    </TableCell>
                    <TableCell
                      sx={{ cursor: 'pointer', fontWeight: 'bold' }}
                      onClick={() => handleSort('hostname')}
                    >
                      Hostname{' '}
                      {sortField === 'hostname' &&
                        (sortOrder === 'asc' ? '↑' : '↓')}
                    </TableCell>
                    <TableCell
                      sx={{ cursor: 'pointer', fontWeight: 'bold' }}
                      onClick={() => handleSort('device_type')}
                    >
                      Type{' '}
                      {sortField === 'device_type' &&
                        (sortOrder === 'asc' ? '↑' : '↓')}
                    </TableCell>
                    <TableCell
                      sx={{ cursor: 'pointer', fontWeight: 'bold' }}
                      onClick={() => handleSort('operating_system')}
                    >
                      OS{' '}
                      {sortField === 'operating_system' &&
                        (sortOrder === 'asc' ? '↑' : '↓')}
                    </TableCell>
                    <TableCell
                      sx={{ cursor: 'pointer', fontWeight: 'bold' }}
                      onClick={() => handleSort('ai_risk_score')}
                    >
                      Risk Score{' '}
                      {sortField === 'ai_risk_score' &&
                        (sortOrder === 'asc' ? '↑' : '↓')}
                    </TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell
                      sx={{ cursor: 'pointer', fontWeight: 'bold' }}
                      onClick={() => handleSort('last_seen')}
                    >
                      Last Seen{' '}
                      {sortField === 'last_seen' &&
                        (sortOrder === 'asc' ? '↑' : '↓')}
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sortedDevices.map((device: Device) => (
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
                      <TableCell>
                        <Chip
                          label={device.ai_risk_score.toFixed(1)}
                          color={getRiskScoreColor(device.ai_risk_score)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={device.status}
                          color={getStatusColor(device.status)}
                          size="small"
                          icon={
                            device.status.toLowerCase() === 'online' ? (
                              <CheckCircleIcon />
                            ) : device.status.toLowerCase() === 'offline' ? (
                              <ErrorIcon />
                            ) : (
                              <WarningIcon />
                            )
                          }
                        />
                      </TableCell>
                      <TableCell>
                        {device.last_seen
                          ? new Date(device.last_seen).toLocaleString()
                          : 'Never'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {/* Remove from Management Dialog */}
      <Dialog open={removeDialog} onClose={() => setRemoveDialog(false)}>
        <DialogTitle>Remove Devices from Management</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to remove {selectedDeviceIds.length} device(s)
            from management? They will be moved back to the Devices page as
            unmanaged devices.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoveDialog(false)}>Cancel</Button>
          <Button
            onClick={handleRemoveFromManaged}
            color="warning"
            variant="contained"
            disabled={unmarkManagedMutation.isLoading}
          >
            {unmarkManagedMutation.isLoading ? (
              <CircularProgress size={20} />
            ) : (
              'Remove from Management'
            )}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Set Password Dialog */}
      <Dialog
        open={passwordDialog}
        onClose={() => setPasswordDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Set SSH Password for Selected Devices</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            Set SSH password for {selectedDeviceIds.length} selected device(s).
          </DialogContentText>
          <TextField
            autoFocus
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
            onClick={() =>
              setBulkPasswordMutation.mutate({
                deviceIds: selectedDeviceIds,
                password: bulkPassword,
              })
            }
            variant="contained"
            disabled={!bulkPassword || setBulkPasswordMutation.isLoading}
          >
            {setBulkPasswordMutation.isLoading ? (
              <CircularProgress size={20} />
            ) : (
              'Set Password'
            )}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Security Reports Dialog */}
      <Dialog
        open={securityReportDialog}
        onClose={() => setSecurityReportDialog(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>Security Audit Reports</DialogTitle>
        <DialogContent>
          <Box sx={{ mb: 2 }}>
            <Typography variant="h6" gutterBottom>
              Summary
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} sm={4}>
                <Card>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>
                      Total Devices Audited
                    </Typography>
                    <Typography variant="h4">
                      {securityReports.length}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Card>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>
                      Average Security Score
                    </Typography>
                    <Typography
                      variant="h4"
                      color={
                        securityReports.length > 0
                          ? securityReports.reduce(
                              (acc, r) => acc + r.overall_score,
                              0
                            ) /
                              securityReports.length >=
                            80
                            ? 'success.main'
                            : 'warning.main'
                          : 'text.primary'
                      }
                    >
                      {securityReports.length > 0
                        ? (
                            securityReports.reduce(
                              (acc, r) => acc + r.overall_score,
                              0
                            ) / securityReports.length
                          ).toFixed(1)
                        : 'N/A'}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Card>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>
                      Critical Issues
                    </Typography>
                    <Typography variant="h4" color="error.main">
                      {securityReports.reduce(
                        (acc, r) =>
                          acc +
                          Object.values(r.categories).reduce(
                            (catAcc: number, cat: any) =>
                              catAcc + cat.critical_issues,
                            0
                          ),
                        0
                      )}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Box>

          {securityReports.map((report, index) => (
            <Accordion key={index} sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 2,
                    width: '100%',
                  }}
                >
                  <Typography variant="h6">
                    {report.hostname || report.ip_address}
                  </Typography>
                  <Chip
                    label={`Score: ${report.overall_score}`}
                    color={
                      report.overall_score >= 80
                        ? 'success'
                        : report.overall_score >= 60
                        ? 'warning'
                        : 'error'
                    }
                    size="small"
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {Object.entries(report.categories).map(
                    ([categoryName, categoryData]: [string, any]) => (
                      <Grid item xs={12} sm={6} key={categoryName}>
                        <Card variant="outlined">
                          <CardContent>
                            <Typography variant="h6" gutterBottom>
                              {categoryName
                                .replace('_', ' ')
                                .replace(/\b\w/g, (l) => l.toUpperCase())}
                            </Typography>
                            <Box
                              sx={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: 2,
                                mb: 1,
                              }}
                            >
                              <Typography variant="h5">
                                {categoryData.score}
                              </Typography>
                              <LinearProgress
                                variant="determinate"
                                value={categoryData.score}
                                sx={{ flexGrow: 1, height: 8, borderRadius: 4 }}
                                color={
                                  categoryData.score >= 80
                                    ? 'success'
                                    : categoryData.score >= 60
                                    ? 'warning'
                                    : 'error'
                                }
                              />
                            </Box>
                            <Typography
                              variant="body2"
                              color="error.main"
                              gutterBottom
                            >
                              Critical Issues: {categoryData.critical_issues}
                            </Typography>
                            <Typography
                              variant="body2"
                              color="warning.main"
                              gutterBottom
                            >
                              Warnings: {categoryData.warnings}
                            </Typography>
                            <Typography variant="body2">
                              {categoryData.details}
                            </Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    )
                  )}
                </Grid>
                <Box sx={{ mt: 2 }}>
                  <Typography variant="h6" gutterBottom>
                    Recommendations
                  </Typography>
                  <Box component="ul" sx={{ pl: 2 }}>
                    {report.recommendations.map(
                      (rec: string, recIndex: number) => (
                        <Typography
                          component="li"
                          key={recIndex}
                          variant="body2"
                          sx={{ mb: 0.5 }}
                        >
                          {rec}
                        </Typography>
                      )
                    )}
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

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ManagedDevices;
