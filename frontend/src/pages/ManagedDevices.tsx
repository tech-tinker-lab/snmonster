
import React, { useState, useEffect } from 'react';
// ...existing code...
import DeviceCard, { Device } from '../components/DeviceCard';
import { deviceAPI } from '../services/api';
import { getAverageSecurityScore, getCriticalIssuesCount, formatCategoryName, updateBulkCredentials, updateSingleCredentials } from '../utils/managedDevicesUtils';
import { Box, Card, CardContent, Typography, Grid, Button, TextField, Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions, Snackbar, Alert, Accordion, AccordionSummary, AccordionDetails, Chip, LinearProgress, CircularProgress, Menu, MenuItem } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';


const ManagedDevices: React.FC = () => {
  // State
  const [devices, setDevices] = useState<Device[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<number[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' | 'warning' }>({ open: false, message: '', severity: 'success' });
  const [removeDialog, setRemoveDialog] = useState(false);
  const [passwordDialog, setPasswordDialog] = useState(false);
  const [bulkUsername, setBulkUsername] = useState('');
  const [bulkPassword, setBulkPassword] = useState('');
  const [securityReportDialog, setSecurityReportDialog] = useState(false);
  const [securityReports, setSecurityReports] = useState<any[]>([]);
  const [credentialsDialog, setCredentialsDialog] = useState<{ open: boolean; device: Device | null }>({ open: false, device: null });
  const [credentialsForm, setCredentialsForm] = useState<{ username: string; password: string }>({ username: '', password: '' });

  // Fetch devices
  const fetchDevices = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await deviceAPI.getManagedDevices();
      setDevices(response.data.devices);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch devices');
    } finally {
      setIsLoading(false);
    }
  };
  useEffect(() => { fetchDevices(); }, []);

  // Filtered devices
  const filteredDevices = devices.filter(
    (device) =>
      device.ip_address.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (device.hostname && device.hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
      device.device_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.operating_system.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Handlers
  const handleDeviceSelect = (deviceId: number) => {
    setSelectedDeviceIds((prev) => prev.includes(deviceId) ? prev.filter(id => id !== deviceId) : [...prev, deviceId]);
  };
  const handleRemoveFromManaged = async () => {
    // Dummy: just remove from UI
    setDevices(devices.filter(d => !selectedDeviceIds.includes(d.id)));
    setSelectedDeviceIds([]);
    setRemoveDialog(false);
    setSnackbar({ open: true, message: 'Devices removed from management', severity: 'success' });
  };
  const handleBulkCredentials = async () => {
    try {
      await updateBulkCredentials(deviceAPI, selectedDeviceIds, bulkUsername, bulkPassword);
      setSnackbar({ open: true, message: `SSH credentials updated for ${selectedDeviceIds.length} devices`, severity: 'success' });
      setPasswordDialog(false);
      setBulkUsername('');
      setBulkPassword('');
      fetchDevices();
    } catch (error) {
      setSnackbar({ open: true, message: 'Failed to update SSH credentials', severity: 'error' });
    }
  };
  const handleSingleCredentials = async () => {
    if (!credentialsDialog.device) return;
    try {
      await updateSingleCredentials(deviceAPI, credentialsDialog.device.id, credentialsForm.username, credentialsForm.password);
      setSnackbar({ open: true, message: `SSH credentials updated for ${credentialsDialog.device.hostname || credentialsDialog.device.ip_address}`, severity: 'success' });
      setCredentialsDialog({ open: false, device: null });
      setCredentialsForm({ username: '', password: '' });
      fetchDevices();
    } catch (error) {
      setSnackbar({ open: true, message: 'Failed to update SSH credentials', severity: 'error' });
    }
  };
  const handleFetchSecurityReports = async () => {
    // Dummy: just show dialog with fake data
    setSecurityReports(devices.map(d => ({
      hostname: d.hostname,
      ip_address: d.ip_address,
      overall_score: Math.floor(Math.random() * 100),
      categories: {
        os_security: { score: Math.floor(Math.random() * 100), critical_issues: Math.floor(Math.random() * 3), warnings: Math.floor(Math.random() * 5), details: 'Sample details.' },
        network: { score: Math.floor(Math.random() * 100), critical_issues: Math.floor(Math.random() * 2), warnings: Math.floor(Math.random() * 4), details: 'Sample details.' }
      },
      recommendations: ['Update OS', 'Change default password']
    })));
    setSecurityReportDialog(true);
  };

  // Render
  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', color: 'primary.main' }}>
          Managed Devices
        </Typography>
        <Button variant="outlined" onClick={fetchDevices} disabled={isLoading}>Refresh</Button>
      </Box>
      <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
        <TextField
          placeholder="Search devices..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          sx={{ minWidth: 300 }}
        />
        <Button variant="contained" color="warning" disabled={selectedDeviceIds.length === 0} onClick={() => setRemoveDialog(true)}>
          Remove from Management ({selectedDeviceIds.length})
        </Button>
        <Button variant="outlined" onClick={() => setPasswordDialog(true)} disabled={selectedDeviceIds.length === 0}>
          Set SSH Credentials
        </Button>
        <Button variant="outlined" onClick={handleFetchSecurityReports} disabled={devices.length === 0}>
          View Security Reports
        </Button>
      </Box>
      {isLoading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}><CircularProgress /></Box>
      ) : error ? (
        <Box sx={{ p: 3 }}><Typography color="error">Error: {error}</Typography><Button onClick={fetchDevices}>Retry</Button></Box>
      ) : (
        <Grid container spacing={3}>
          {filteredDevices.map((device) => (
            <Grid item xs={12} sm={6} md={4} lg={3} key={device.id}>
              <DeviceCard
                device={device}
                selected={selectedDeviceIds.includes(device.id)}
                onSelect={() => handleDeviceSelect(device.id)}
                onSetSSH={() => {
                  setCredentialsDialog({ open: true, device });
                  setCredentialsForm({ username: device.ssh_username || '', password: '' });
                }}
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
            Are you sure you want to remove {selectedDeviceIds.length} device(s) from management?
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoveDialog(false)}>Cancel</Button>
          <Button onClick={handleRemoveFromManaged} color="warning" variant="contained">
            Remove
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
            value={bulkUsername}
            onChange={(e) => setBulkUsername(e.target.value)}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="SSH Password"
            type="password"
            fullWidth
            value={bulkPassword}
            onChange={(e) => setBulkPassword(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPasswordDialog(false)}>Cancel</Button>
          <Button onClick={handleBulkCredentials} variant="contained" disabled={!bulkUsername || !bulkPassword}>
            Save Credentials
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
              <Grid item xs={12} sm={4}><Card><CardContent><Typography color="textSecondary" gutterBottom>Average Security Score</Typography><Typography variant="h4" color={(() => { const avg = getAverageSecurityScore(securityReports); return avg !== null && avg >= 80 ? 'success.main' : avg !== null && avg >= 60 ? 'warning.main' : 'text.primary'; })()}>{securityReports.length > 0 ? getAverageSecurityScore(securityReports)?.toFixed(1) : 'N/A'}</Typography></CardContent></Card></Grid>
              <Grid item xs={12} sm={4}><Card><CardContent><Typography color="textSecondary" gutterBottom>Critical Issues</Typography><Typography variant="h4" color="error.main">{getCriticalIssuesCount(securityReports)}</Typography></CardContent></Card></Grid>
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
                        <Typography variant="h6" gutterBottom>{formatCategoryName(categoryName)}</Typography>
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
            value={credentialsForm.username}
            onChange={(e) => setCredentialsForm({ ...credentialsForm, username: e.target.value })}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="SSH Password"
            type="password"
            fullWidth
            value={credentialsForm.password}
            onChange={(e) => setCredentialsForm({ ...credentialsForm, password: e.target.value })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCredentialsDialog({ open: false, device: null })}>Cancel</Button>
          <Button onClick={handleSingleCredentials} variant="contained" disabled={!credentialsForm.username || !credentialsForm.password}>
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


