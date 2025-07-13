import React from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Settings as SettingsIcon,
  BugReport as BugReportIcon,
} from '@mui/icons-material';
import ApiTest from '../components/ApiTest';
import CorsDebug from '../components/CorsDebug';

const Settings: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" component="h1" sx={{ mb: 3 }}>
        Settings & Debug Tools
      </Typography>

      {/* Debug Tools Section */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <BugReportIcon sx={{ mr: 1 }} />
            <Typography variant="h6">Debug Tools</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <CorsDebug />
          <Divider sx={{ my: 2 }} />
          <ApiTest />
        </AccordionDetails>
      </Accordion>

      {/* System Settings Section */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <SettingsIcon sx={{ mr: 1 }} />
            <Typography variant="h6">System Settings</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Card>
            <CardContent>
              <Typography variant="body1">
                System settings and configuration options will be implemented here.
              </Typography>
            </CardContent>
          </Card>
        </AccordionDetails>
      </Accordion>
    </Box>
  );
};

export default Settings; 