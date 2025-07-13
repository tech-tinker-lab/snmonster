import React from 'react';
import { Box, Typography, Card, CardContent, Button } from '@mui/material';

const NetworkScan: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" component="h1" sx={{ mb: 3 }}>
        Network Scan
      </Typography>
      <Card>
        <CardContent>
          <Typography variant="body1">
            Network scanning functionality will be implemented here.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default NetworkScan; 