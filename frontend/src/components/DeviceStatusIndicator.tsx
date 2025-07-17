import React from 'react';
import { Box, Chip, alpha } from '@mui/material';
import { Warning as WarningIcon } from '@mui/icons-material';

interface DeviceStatusIndicatorProps {
  status: string;
  riskScore: number;
}

const DeviceStatusIndicator: React.FC<DeviceStatusIndicatorProps> = ({
  status,
  riskScore,
}) => {
  const isHighRisk = riskScore > 0.7;

  const getStatusConfig = () => {
    switch (status.toLowerCase()) {
      case 'online':
        return {
          color: '#4caf50',
          label: 'Online',
          hasAnimation: true,
        };
      case 'offline':
        return {
          color: '#f44336',
          label: 'Offline',
          hasAnimation: false,
        };
      case 'maintenance':
        return {
          color: '#ff9800',
          label: 'Maintenance',
          hasAnimation: false,
        };
      default:
        return {
          color: '#9e9e9e',
          label: 'Unknown',
          hasAnimation: false,
        };
    }
  };

  const config = getStatusConfig();

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Box
        sx={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          backgroundColor: config.color,
          boxShadow: config.hasAnimation ? `0 0 6px ${config.color}` : 'none',
          ...(config.hasAnimation && {
            animation: 'pulse 2s infinite',
            '@keyframes pulse': {
              '0%': { boxShadow: `0 0 6px ${config.color}` },
              '50%': {
                boxShadow: `0 0 12px ${config.color}, 0 0 18px ${config.color}`,
              },
              '100%': { boxShadow: `0 0 6px ${config.color}` },
            },
          }),
        }}
      />
      <Chip
        label={config.label}
        size="small"
        sx={{
          backgroundColor: alpha(config.color, 0.1),
          color: config.color,
          border: `1px solid ${alpha(config.color, 0.3)}`,
          fontWeight: 600,
        }}
      />
      {isHighRisk && (
        <WarningIcon sx={{ color: '#f44336', fontSize: 16, ml: 0.5 }} />
      )}
    </Box>
  );
};

export default DeviceStatusIndicator;
