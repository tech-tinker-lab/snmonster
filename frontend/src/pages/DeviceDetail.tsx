import React from 'react';
import { Box, Typography, Card, CardContent } from '@mui/material';

const DeviceDetail: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" component="h1" sx={{ mb: 3 }}>
        Device Details
      </Typography>
      <Card>
        <CardContent>
          <Typography variant="body1">
            Device detail functionality will be implemented here.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default DeviceDetail; 