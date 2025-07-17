import React from 'react';
import { Box, Chip, alpha } from '@mui/material';
import {
  Computer as ComputerIcon,
  Router as RouterIcon,
  Smartphone as SmartphoneIcon,
  Print as PrintIcon,
  DevicesOther as DevicesIcon,
} from '@mui/icons-material';

interface DeviceTypeIndicatorProps {
  deviceType: string;
}

const DeviceTypeIndicator: React.FC<DeviceTypeIndicatorProps> = ({
  deviceType,
}) => {
  const getDeviceConfig = () => {
    switch (deviceType.toLowerCase()) {
      case 'computer':
        return {
          icon: <ComputerIcon />,
          color: '#2196f3',
        };
      case 'router':
        return {
          icon: <RouterIcon />,
          color: '#ff9800',
        };
      case 'mobile':
        return {
          icon: <SmartphoneIcon />,
          color: '#9c27b0',
        };
      case 'printer':
        return {
          icon: <PrintIcon />,
          color: '#607d8b',
        };
      default:
        return {
          icon: <DevicesIcon />,
          color: '#00d4aa',
        };
    }
  };

  const config = getDeviceConfig();

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Box
        sx={{
          p: 0.75,
          borderRadius: '8px',
          backgroundColor: alpha(config.color, 0.1),
          color: config.color,
          border: `1px solid ${alpha(config.color, 0.2)}`,
        }}
      >
        {config.icon}
      </Box>
      <Chip
        label={deviceType}
        size="small"
        sx={{
          backgroundColor: alpha(config.color, 0.1),
          color: config.color,
          border: `1px solid ${alpha(config.color, 0.3)}`,
          fontWeight: 600,
          textTransform: 'capitalize',
        }}
      />
    </Box>
  );
};

export default DeviceTypeIndicator;
