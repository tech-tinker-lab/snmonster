import React, { useState } from 'react';
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
  Button,
  alpha,
} from '@mui/material';
import {
  DevicesOther as DevicesIcon,
  Speed as SpeedIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  NetworkCheck as NetworkCheckIcon,
  Computer as ComputerIcon,
  Router as RouterIcon,
  Smartphone as SmartphoneIcon,
  Print as PrintIcon,
  Shield as ShieldIcon,
  Timeline as TimelineIcon,
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
  const onlineDevices = devices.filter((d) => d.status === 'online').length;
  const offlineDevices = totalDevices - onlineDevices;
  const highRiskDevices = devices.filter((d) => d.ai_risk_score > 0.7).length;

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
    trend?: 'up' | 'down' | 'stable';
  }> = ({ title, value, icon, color, subtitle, trend }) => (
    <Card
      sx={{
        height: '100%',
        position: 'relative',
        overflow: 'hidden',
        transition: 'all 0.3s ease-in-out',
        '&:hover': {
          transform: 'translateY(-4px)',
          boxShadow: `0 12px 30px ${alpha(color, 0.2)}`,
        },
        '&::before': {
          content: '""',
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: 4,
          background: `linear-gradient(90deg, ${color}, ${alpha(color, 0.7)})`,
        },
      }}
    >
      <CardContent sx={{ position: 'relative' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <Box
            sx={{
              color,
              mr: 2,
              p: 1,
              borderRadius: '12px',
              backgroundColor: alpha(color, 0.1),
              border: `1px solid ${alpha(color, 0.2)}`,
            }}
          >
            {icon}
          </Box>
          <Box sx={{ flexGrow: 1 }}>
            <Typography
              variant="h6"
              component="div"
              sx={{
                color: 'text.primary',
                fontWeight: 600,
              }}
            >
              {title}
            </Typography>
          </Box>
          {trend && (
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              {trend === 'up' && (
                <TrendingUpIcon sx={{ color: '#4caf50', fontSize: 20 }} />
              )}
              {trend === 'down' && (
                <TrendingDownIcon sx={{ color: '#f44336', fontSize: 20 }} />
              )}
              {trend === 'stable' && (
                <TimelineIcon sx={{ color: '#ff9800', fontSize: 20 }} />
              )}
            </Box>
          )}
        </Box>
        <Typography
          variant="h3"
          component="div"
          sx={{
            mb: 1,
            color,
            fontWeight: 'bold',
            background: `linear-gradient(45deg, ${color}, ${alpha(
              color,
              0.7
            )})`,
            backgroundClip: 'text',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}
        >
          {value}
        </Typography>
        {subtitle && (
          <Typography
            variant="body2"
            sx={{
              color: 'text.secondary',
              fontWeight: 500,
            }}
          >
            {subtitle}
          </Typography>
        )}
      </CardContent>
    </Card>
  );

  const getDeviceIcon = (deviceType: string) => {
    switch (deviceType.toLowerCase()) {
      case 'computer':
        return <ComputerIcon />;
      case 'router':
        return <RouterIcon />;
      case 'mobile':
        return <SmartphoneIcon />;
      case 'printer':
        return <PrintIcon />;
      default:
        return <DevicesIcon />;
    }
  };

  const getDeviceTypeColor = (deviceType: string) => {
    switch (deviceType.toLowerCase()) {
      case 'computer':
        return '#2196f3';
      case 'router':
        return '#ff9800';
      case 'mobile':
        return '#9c27b0';
      case 'printer':
        return '#607d8b';
      default:
        return '#00d4aa';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'online':
        return '#4caf50';
      case 'offline':
        return '#f44336';
      case 'maintenance':
        return '#ff9800';
      default:
        return '#9e9e9e';
    }
  };

  const RecentActivityCard: React.FC = () => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <TimelineIcon sx={{ color: 'primary.main', mr: 1 }} />
          <Typography variant="h6" component="div">
            Recent Activity
          </Typography>
        </Box>
        <List dense>
          {devices.slice(0, 5).map((device) => {
            const deviceColor = getDeviceTypeColor(device.device_type);
            const statusColor = getStatusColor(device.status);

            return (
              <ListItem
                key={device.id}
                sx={{
                  borderRadius: '8px',
                  mb: 1,
                  border: `1px solid ${alpha(deviceColor, 0.1)}`,
                  transition: 'all 0.2s ease',
                  '&:hover': {
                    backgroundColor: alpha(deviceColor, 0.05),
                    transform: 'translateX(4px)',
                  },
                }}
              >
                <ListItemIcon>
                  <Box
                    sx={{
                      p: 1,
                      borderRadius: '8px',
                      backgroundColor: alpha(deviceColor, 0.1),
                      color: deviceColor,
                      border: `1px solid ${alpha(deviceColor, 0.2)}`,
                    }}
                  >
                    {getDeviceIcon(device.device_type)}
                  </Box>
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                      {device.hostname || device.ip_address}
                    </Typography>
                  }
                  secondary={
                    <Box
                      sx={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 1,
                        mt: 0.5,
                      }}
                    >
                      <Chip
                        label={device.device_type}
                        size="small"
                        sx={{
                          backgroundColor: alpha(deviceColor, 0.1),
                          color: deviceColor,
                          border: `1px solid ${alpha(deviceColor, 0.3)}`,
                          fontSize: '0.7rem',
                          height: '20px',
                        }}
                      />
                      <Typography
                        variant="caption"
                        sx={{ color: 'text.secondary' }}
                      >
                        {device.operating_system}
                      </Typography>
                    </Box>
                  }
                />
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Chip
                    label={device.status}
                    size="small"
                    sx={{
                      backgroundColor: alpha(statusColor, 0.1),
                      color: statusColor,
                      border: `1px solid ${alpha(statusColor, 0.3)}`,
                      fontWeight: 600,
                      '& .MuiChip-label': {
                        textTransform: 'capitalize',
                      },
                    }}
                  />
                  {device.ai_risk_score > 0.7 && (
                    <WarningIcon sx={{ color: '#f44336', fontSize: 16 }} />
                  )}
                </Box>
              </ListItem>
            );
          })}
        </List>
      </CardContent>
    </Card>
  );

  const SecurityOverviewCard: React.FC = () => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <ShieldIcon sx={{ color: '#f44336', mr: 1 }} />
          <Typography variant="h6" component="div">
            Security Overview
          </Typography>
        </Box>

        {/* High Risk Devices */}
        <Box sx={{ mb: 3 }}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              mb: 1,
            }}
          >
            <Typography variant="body2" sx={{ fontWeight: 600 }}>
              High Risk Devices
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography
                variant="body2"
                sx={{ color: '#f44336', fontWeight: 'bold' }}
              >
                {highRiskDevices}
              </Typography>
              <WarningIcon sx={{ color: '#f44336', fontSize: 16 }} />
            </Box>
          </Box>
          <LinearProgress
            variant="determinate"
            value={(highRiskDevices / totalDevices) * 100}
            sx={{
              height: 8,
              borderRadius: 4,
              backgroundColor: alpha('#f44336', 0.1),
              '& .MuiLinearProgress-bar': {
                borderRadius: 4,
                backgroundColor: '#f44336',
                boxShadow: `0 0 8px ${alpha('#f44336', 0.4)}`,
              },
            }}
          />
        </Box>

        {/* Online Devices */}
        <Box sx={{ mb: 3 }}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              mb: 1,
            }}
          >
            <Typography variant="body2" sx={{ fontWeight: 600 }}>
              Online Devices
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography
                variant="body2"
                sx={{ color: '#4caf50', fontWeight: 'bold' }}
              >
                {onlineDevices}
              </Typography>
              <CheckCircleIcon sx={{ color: '#4caf50', fontSize: 16 }} />
            </Box>
          </Box>
          <LinearProgress
            variant="determinate"
            value={(onlineDevices / totalDevices) * 100}
            sx={{
              height: 8,
              borderRadius: 4,
              backgroundColor: alpha('#4caf50', 0.1),
              '& .MuiLinearProgress-bar': {
                borderRadius: 4,
                backgroundColor: '#4caf50',
                boxShadow: `0 0 8px ${alpha('#4caf50', 0.4)}`,
              },
            }}
          />
        </Box>

        {/* Network Health Score */}
        <Box sx={{ mb: 2 }}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              mb: 1,
            }}
          >
            <Typography variant="body2" sx={{ fontWeight: 600 }}>
              Network Health Score
            </Typography>
            <Typography
              variant="body2"
              sx={{ color: '#00d4aa', fontWeight: 'bold' }}
            >
              {Math.round((onlineDevices / totalDevices) * 100)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={(onlineDevices / totalDevices) * 100}
            sx={{
              height: 8,
              borderRadius: 4,
              backgroundColor: alpha('#00d4aa', 0.1),
              '& .MuiLinearProgress-bar': {
                borderRadius: 4,
                background: 'linear-gradient(90deg, #00d4aa, #4dffdb)',
                boxShadow: `0 0 8px ${alpha('#00d4aa', 0.4)}`,
              },
            }}
          />
        </Box>

        <Box sx={{ display: 'flex', gap: 1, mt: 2, flexWrap: 'wrap' }}>
          {highRiskDevices === 0 ? (
            <Chip
              icon={<CheckCircleIcon />}
              label="System Secure"
              sx={{
                backgroundColor: alpha('#4caf50', 0.1),
                color: '#4caf50',
                border: `1px solid ${alpha('#4caf50', 0.3)}`,
                fontWeight: 600,
              }}
              size="small"
            />
          ) : (
            <Chip
              icon={<WarningIcon />}
              label={`${highRiskDevices} Risk Alert${
                highRiskDevices > 1 ? 's' : ''
              }`}
              sx={{
                backgroundColor: alpha('#f44336', 0.1),
                color: '#f44336',
                border: `1px solid ${alpha('#f44336', 0.3)}`,
                fontWeight: 600,
              }}
              size="small"
            />
          )}

          <Chip
            icon={<NetworkCheckIcon />}
            label="Real-time Scan"
            sx={{
              backgroundColor: alpha('#2196f3', 0.1),
              color: '#2196f3',
              border: `1px solid ${alpha('#2196f3', 0.3)}`,
              fontWeight: 600,
            }}
            size="small"
          />
        </Box>
      </CardContent>
    </Card>
  );

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

      {/* Enhanced Network Statistics */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Devices"
            value={networkStats.total_devices}
            icon={<DevicesIcon />}
            color="#00d4aa"
            subtitle="Discovered devices"
            trend="up"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Online"
            value={networkStats.online_devices}
            icon={<CheckCircleIcon />}
            color="#4caf50"
            subtitle="Active connections"
            trend={
              networkStats.online_devices > networkStats.offline_devices
                ? 'up'
                : 'down'
            }
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="High Risk"
            value={networkStats.high_risk_devices}
            icon={<WarningIcon />}
            color="#f44336"
            subtitle="Security alerts"
            trend={networkStats.high_risk_devices > 0 ? 'down' : 'stable'}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Response Time"
            value={`${networkStats.average_response_time}ms`}
            icon={<SpeedIcon />}
            color="#2196f3"
            subtitle="Network latency"
            trend="stable"
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
