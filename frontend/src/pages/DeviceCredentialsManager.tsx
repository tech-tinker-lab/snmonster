import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  TextField,
  Button,
  Chip,
  Alert,
  IconButton,
  Collapse,
  Divider,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Save as SaveIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
} from '@mui/icons-material';
import { deviceAPI } from '../services/api';

interface Device {
  id: number;
  ip_address: string;
  hostname?: string;
  ssh_username?: string;
  ssh_password?: string;
  is_managed: boolean;
  status: string;
  device_type: string;
  operating_system: string;
}

const DeviceCredentialsManager: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedDevice, setExpandedDevice] = useState<number | null>(null);
  const [credentials, setCredentials] = useState<{ [key: number]: { username: string; password: string; showPassword: boolean } }>({});
  const [updateStatus, setUpdateStatus] = useState<{ [key: number]: { loading: boolean; message: string; severity: 'success' | 'error' | 'info' } }>({});

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    try {
      const response = await deviceAPI.getManagedDevices();
      setDevices(response.data);
      
      // Initialize credentials state
      const initialCredentials: { [key: number]: { username: string; password: string; showPassword: boolean } } = {};
      response.data.forEach((device: Device) => {
        initialCredentials[device.id] = {
          username: device.ssh_username || '',
          password: '',
          showPassword: false
        };
      });
      setCredentials(initialCredentials);
    } catch (error) {
      console.error('Failed to fetch devices:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCredentialChange = (deviceId: number, field: 'username' | 'password', value: string) => {
    setCredentials(prev => ({
      ...prev,
      [deviceId]: {
        ...prev[deviceId],
        [field]: value
      }
    }));
  };

  const togglePasswordVisibility = (deviceId: number) => {
    setCredentials(prev => ({
      ...prev,
      [deviceId]: {
        ...prev[deviceId],
        showPassword: !prev[deviceId].showPassword
      }
    }));
  };

  const updateDeviceCredentials = async (device: Device) => {
    const deviceCredentials = credentials[device.id];
    if (!deviceCredentials.username || !deviceCredentials.password) {
      setUpdateStatus(prev => ({
        ...prev,
        [device.id]: {
          loading: false,
          message: 'Both username and password are required',
          severity: 'error'
        }
      }));
      return;
    }

    setUpdateStatus(prev => ({
      ...prev,
      [device.id]: {
        loading: true,
        message: 'Updating credentials...',
        severity: 'info'
      }
    }));

    try {
      await deviceAPI.updateDevice(device.id, {
        ssh_username: deviceCredentials.username,
        ssh_password: deviceCredentials.password
      });

      setUpdateStatus(prev => ({
        ...prev,
        [device.id]: {
          loading: false,
          message: 'Credentials updated successfully!',
          severity: 'success'
        }
      }));

      // Clear password field for security
      setCredentials(prev => ({
        ...prev,
        [device.id]: {
          ...prev[device.id],
          password: ''
        }
      }));

      // Refresh devices to get updated ssh_username
      setTimeout(() => {
        fetchDevices();
      }, 1000);
    } catch (error) {
      setUpdateStatus(prev => ({
        ...prev,
        [device.id]: {
          loading: false,
          message: 'Failed to update credentials',
          severity: 'error'
        }
      }));
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'online': return 'success';
      case 'offline': return 'error';
      default: return 'warning';
    }
  };

  if (loading) return <Typography>Loading devices...</Typography>;

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Device SSH Credentials Manager
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Manage SSH credentials for your managed devices to enable terminal access and remote operations.
      </Typography>

      <Grid container spacing={2}>
        {devices.map((device) => (
          <Grid item xs={12} md={6} lg={4} key={device.id}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                  <Box>
                    <Typography variant="h6" noWrap>
                      {device.hostname || device.ip_address}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {device.ip_address}
                    </Typography>
                  </Box>
                  <Chip 
                    label={device.status} 
                    color={getStatusColor(device.status) as any}
                    size="small"
                  />
                </Box>

                <Box sx={{ mb: 2 }}>
                  <Chip label={device.device_type} size="small" sx={{ mr: 1 }} />
                  <Chip label={device.operating_system} size="small" />
                </Box>

                {device.ssh_username && (
                  <Box sx={{ mb: 2 }}>
                    <Chip 
                      label={`SSH: ${device.ssh_username}`} 
                      color="primary" 
                      variant="outlined" 
                      size="small"
                    />
                  </Box>
                )}

                <Button
                  fullWidth
                  variant={expandedDevice === device.id ? "contained" : "outlined"}
                  onClick={() => setExpandedDevice(expandedDevice === device.id ? null : device.id)}
                  endIcon={expandedDevice === device.id ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                  sx={{ mb: 2 }}
                >
                  {device.ssh_username ? 'Update' : 'Set'} SSH Credentials
                </Button>

                <Collapse in={expandedDevice === device.id}>
                  <Divider sx={{ mb: 2 }} />
                  
                  <TextField
                    fullWidth
                    label="SSH Username"
                    variant="outlined"
                    size="small"
                    value={credentials[device.id]?.username || ''}
                    onChange={(e) => handleCredentialChange(device.id, 'username', e.target.value)}
                    sx={{ mb: 2 }}
                    placeholder="e.g., root, admin, ubuntu, rock"
                  />

                  <TextField
                    fullWidth
                    label="SSH Password"
                    variant="outlined"
                    size="small"
                    type={credentials[device.id]?.showPassword ? 'text' : 'password'}
                    value={credentials[device.id]?.password || ''}
                    onChange={(e) => handleCredentialChange(device.id, 'password', e.target.value)}
                    sx={{ mb: 2 }}
                    InputProps={{
                      endAdornment: (
                        <IconButton
                          onClick={() => togglePasswordVisibility(device.id)}
                          edge="end"
                          size="small"
                        >
                          {credentials[device.id]?.showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                        </IconButton>
                      )
                    }}
                  />

                  <Button
                    fullWidth
                    variant="contained"
                    onClick={() => updateDeviceCredentials(device)}
                    disabled={updateStatus[device.id]?.loading || !credentials[device.id]?.username || !credentials[device.id]?.password}
                    startIcon={<SaveIcon />}
                    sx={{ mb: 2 }}
                  >
                    {updateStatus[device.id]?.loading ? 'Saving...' : 'Save Credentials'}
                  </Button>

                  {updateStatus[device.id]?.message && (
                    <Alert severity={updateStatus[device.id].severity}>
                      {updateStatus[device.id].message}
                    </Alert>
                  )}
                </Collapse>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default DeviceCredentialsManager;
