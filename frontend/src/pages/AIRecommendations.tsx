import React from 'react';
import { Box, Typography, Card, CardContent } from '@mui/material';

const AIRecommendations: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" component="h1" sx={{ mb: 3 }}>
        AI Recommendations
      </Typography>
      <Card>
        <CardContent>
          <Typography variant="body1">
            AI-powered recommendations will be implemented here.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default AIRecommendations; 