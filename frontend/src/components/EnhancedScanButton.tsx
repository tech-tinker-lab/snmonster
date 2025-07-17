import React from 'react';
import { Button, Box, Chip, alpha } from '@mui/material';
import {
  PlayArrow as PlayArrowIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';

interface EnhancedScanButtonProps {
  isScanning: boolean;
  onStartScan: () => void;
  onStopScan: () => void;
  onRefresh: () => void;
}

const EnhancedScanButton: React.FC<EnhancedScanButtonProps> = ({
  isScanning,
  onStartScan,
  onStopScan,
  onRefresh,
}) => {
  return (
    <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
      {isScanning ? (
        <>
          <Chip
            icon={<StopIcon />}
            label="Scanning Active"
            sx={{
              backgroundColor: alpha('#ff9800', 0.1),
              color: '#ff9800',
              border: `1px solid ${alpha('#ff9800', 0.3)}`,
              fontWeight: 600,
              animation: 'pulse 2s infinite',
              '@keyframes pulse': {
                '0%': { opacity: 1 },
                '50%': { opacity: 0.7 },
                '100%': { opacity: 1 },
              },
            }}
          />
          <Button
            variant="outlined"
            color="error"
            onClick={onStopScan}
            startIcon={<StopIcon />}
            sx={{
              borderRadius: '8px',
              textTransform: 'none',
              fontWeight: 600,
            }}
          >
            Stop Scan
          </Button>
        </>
      ) : (
        <Button
          variant="contained"
          color="primary"
          onClick={onStartScan}
          startIcon={<PlayArrowIcon />}
          sx={{
            borderRadius: '8px',
            textTransform: 'none',
            fontWeight: 600,
            background: 'linear-gradient(45deg, #00d4aa, #4dffdb)',
            '&:hover': {
              background: 'linear-gradient(45deg, #00a382, #00d4aa)',
            },
          }}
        >
          Start Network Scan
        </Button>
      )}

      <Button
        variant="outlined"
        onClick={onRefresh}
        startIcon={<RefreshIcon />}
        sx={{
          borderRadius: '8px',
          textTransform: 'none',
          fontWeight: 600,
        }}
      >
        Refresh
      </Button>
    </Box>
  );
};

export default EnhancedScanButton;
