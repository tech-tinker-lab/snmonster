import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
  Button,
} from '@mui/material';
import {
  Devices as DevicesIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
} from '@mui/icons-material';
import { useQuery } from 'react-query';
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
}

interface NetworkStats {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  high_risk_devices: number;
  average_response_time: number;
}

const Dashboard: React.FC = () => {
  const [isScanning, setIsScanning] = useState(false);

  // Fetch devices
  const { data: devicesData, refetch: refetchDevices } = useQuery(
    'devices',
    async () => {
      const response = await deviceAPI.getDevices();
      return response.data;
    },
    { refetchInterval: 30000 } // Refetch every 30 seconds
  );

  // Fetch scan status
  const { data: scanStatus } = useQuery(
    'scanStatus',
    async () => {
      const response = await deviceAPI.getScanStatus();
      return response.data;
    },
    { refetchInterval: 5000 } // Refetch every 5 seconds
  );

  const devices: Device[] = devicesData?.devices || [];
  const totalDevices = devices.length;
  const onlineDevices = devices.filter(d => d.status === 'online').length;
  const offlineDevices = totalDevices - onlineDevices;
  const highRiskDevices = devices.filter(d => d.ai_risk_score > 0.7).length;

  const networkStats: NetworkStats = {
    total_devices: totalDevices,
    online_devices: onlineDevices,
    offline_devices: offlineDevices,
    high_risk_devices: highRiskDevices,
    average_response_time: 45, // Mock data
  };

  const handleStartScan = async () => {
    try {
      setIsScanning(true);
      await deviceAPI.startScan();
      refetchDevices();
    } catch (error) {
      console.error('Error starting scan:', error);
    } finally {
      setIsScanning(false);
    }
  };

  const handleStopScan = async () => {
    try {
      await deviceAPI.stopScan();
    } catch (error) {
      console.error('Error stopping scan:', error);
    }
  };

  const StatCard: React.FC<{
    title: string;
    value: string | number;
    icon: React.ReactNode;
    color: string;
    subtitle?: string;
  }> = ({ title, value, icon, color, subtitle }) => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <Box sx={{ color, mr: 1 }}>{icon}</Box>
          <Typography variant="h6" component="div">
            {title}
          </Typography>
        </Box>
        <Typography variant="h4" component="div" sx={{ mb: 1 }}>
          {value}
        </Typography>
        {subtitle && (
          <Typography variant="body2" color="text.secondary">
            {subtitle}
          </Typography>
        )}
      </CardContent>
    </Card>
  );

  const RecentActivityCard: React.FC = () => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Typography variant="h6" component="div" sx={{ mb: 2 }}>
          Recent Activity
        </Typography>
        <List dense>
          {devices.slice(0, 5).map((device) => (
            <ListItem key={device.id}>
              <ListItemIcon>
                <DevicesIcon color="primary" />
              </ListItemIcon>
              <ListItemText
                primary={device.hostname || device.ip_address}
                secondary={`${device.device_type} • ${device.operating_system}`}
              />
              <Chip
                label={device.status}
                color={device.status === 'online' ? 'success' : 'error'}
                size="small"
              />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );

  const SecurityOverviewCard: React.FC = () => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Typography variant="h6" component="div" sx={{ mb: 2 }}>
          Security Overview
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="body2">High Risk Devices</Typography>
            <Typography variant="body2">{highRiskDevices}</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={(highRiskDevices / totalDevices) * 100}
            color="error"
            sx={{ height: 8, borderRadius: 4 }}
          />
        </Box>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="body2">Online Devices</Typography>
            <Typography variant="body2">{onlineDevices}</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={(onlineDevices / totalDevices) * 100}
            color="success"
            sx={{ height: 8, borderRadius: 4 }}
          />
        </Box>
        <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
          <Chip
            icon={<CheckCircleIcon />}
            label="System Secure"
            color="success"
            variant="outlined"
            size="small"
          />
          <Chip
            icon={<WarningIcon />}
            label={`${highRiskDevices} Alerts`}
            color="warning"
            variant="outlined"
            size="small"
          />
        </Box>
      </CardContent>
    </Card>
  );

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Network Dashboard
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => refetchDevices()}
          >
            Refresh
          </Button>
          {scanStatus?.is_scanning ? (
            <Button
              variant="contained"
              color="error"
              onClick={handleStopScan}
              disabled={isScanning}
            >
              Stop Scan
            </Button>
          ) : (
            <Button
              variant="contained"
              color="primary"
              onClick={handleStartScan}
              disabled={isScanning}
            >
              Start Scan
            </Button>
          )}
        </Box>
      </Box>

      {/* Network Statistics */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Devices"
            value={networkStats.total_devices}
            icon={<DevicesIcon />}
            color="primary.main"
            subtitle="Discovered devices"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Online"
            value={networkStats.online_devices}
            icon={<CheckCircleIcon />}
            color="success.main"
            subtitle="Active devices"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="High Risk"
            value={networkStats.high_risk_devices}
            icon={<WarningIcon />}
            color="error.main"
            subtitle="Security alerts"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Response Time"
            value={`${networkStats.average_response_time}ms`}
            icon={<SpeedIcon />}
            color="info.main"
            subtitle="Average latency"
          />
        </Grid>
      </Grid>

      {/* Network Overview Cards */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <RecentActivityCard />
        </Grid>
        <Grid item xs={12} md={6}>
          <SecurityOverviewCard />
        </Grid>
      </Grid>

      {/* Scan Status */}
      {scanStatus?.is_scanning && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <TrendingUpIcon sx={{ mr: 1, color: 'primary.main' }} />
              <Typography variant="h6">Network Scan in Progress</Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Scanning network for devices and vulnerabilities...
            </Typography>
            <LinearProgress sx={{ height: 8, borderRadius: 4 }} />
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default Dashboard; 