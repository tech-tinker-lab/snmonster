import React from 'react';
import { Box, Chip, LinearProgress, alpha } from '@mui/material';

interface RiskScoreIndicatorProps {
  riskScore: number;
}

const RiskScoreIndicator: React.FC<RiskScoreIndicatorProps> = ({
  riskScore,
}) => {
  const getRiskConfig = () => {
    if (riskScore >= 0.8) {
      return { color: '#f44336', label: 'High' }; // High risk - Red
    }
    if (riskScore >= 0.6) {
      return { color: '#ff9800', label: 'Medium' }; // Medium risk - Orange
    }
    if (riskScore >= 0.3) {
      return { color: '#ffeb3b', label: 'Low' }; // Low risk - Yellow
    }
    return { color: '#4caf50', label: 'Safe' }; // Safe - Green
  };

  const config = getRiskConfig();
  const percentage = Math.round(riskScore * 100);

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 120 }}>
      <LinearProgress
        variant="determinate"
        value={percentage}
        sx={{
          flexGrow: 1,
          height: 8,
          borderRadius: 4,
          backgroundColor: alpha(config.color, 0.1),
          '& .MuiLinearProgress-bar': {
            borderRadius: 4,
            backgroundColor: config.color,
            boxShadow: `0 0 8px ${alpha(config.color, 0.4)}`,
          },
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
          minWidth: 60,
        }}
      />
    </Box>
  );
};

export default RiskScoreIndicator;
