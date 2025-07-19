import React, { useState } from 'react';
import { Box, Button, Typography, Card, CardContent, Alert } from '@mui/material';
import { deviceAPI, systemAPI } from '../services/api';

const ApiTest: React.FC = () => {
  const [testResults, setTestResults] = useState<{ [key: string]: any }>({});
  const [loading, setLoading] = useState(false);

  const runTests = async () => {
    setLoading(true);
    const results: { [key: string]: any } = {};

    try {
      // Test 1: CORS test
      console.log('Testing CORS endpoint...');
      const corsResponse = await fetch('http://localhost:8004/api/cors-test');
      const corsData = await corsResponse.json();
      results.cors = { success: true, data: corsData };
      console.log('CORS test passed:', corsData);
    } catch (error) {
      results.cors = { success: false, error: error };
      console.error('CORS test failed:', error);
    }

    try {
      // Test 2: Health check
      console.log('Testing health endpoint...');
      const healthResponse = await systemAPI.getHealth();
      results.health = { success: true, data: healthResponse.data };
      console.log('Health test passed:', healthResponse.data);
    } catch (error) {
      results.health = { success: false, error: error };
      console.error('Health test failed:', error);
    }

    try {
      // Test 2: Devices endpoint
      console.log('Testing devices endpoint...');
      const devicesResponse = await deviceAPI.getDevices();
      results.devices = { success: true, data: devicesResponse.data };
      console.log('Devices test passed:', devicesResponse.data);
    } catch (error) {
      results.devices = { success: false, error: error };
      console.error('Devices test failed:', error);
    }

    try {
      // Test 3: Scan status endpoint
      console.log('Testing scan status endpoint...');
      const scanResponse = await deviceAPI.getScanStatus();
      results.scanStatus = { success: true, data: scanResponse.data };
      console.log('Scan status test passed:', scanResponse.data);
    } catch (error) {
      results.scanStatus = { success: false, error: error };
      console.error('Scan status test failed:', error);
    }

    setTestResults(results);
    setLoading(false);
  };

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="h5" gutterBottom>
        API Connection Test
      </Typography>
      
      <Button 
        variant="contained" 
        onClick={runTests} 
        disabled={loading}
        sx={{ mb: 2 }}
      >
        {loading ? 'Testing...' : 'Run API Tests'}
      </Button>

      {Object.keys(testResults).length > 0 && (
        <Box sx={{ mt: 2 }}>
          {Object.entries(testResults).map(([testName, result]) => (
            <Card key={testName} sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {testName.charAt(0).toUpperCase() + testName.slice(1)} Test
                </Typography>
                
                {result.success ? (
                  <Alert severity="success">
                    ✅ Test passed
                    <pre style={{ fontSize: '12px', marginTop: '8px' }}>
                      {JSON.stringify(result.data, null, 2)}
                    </pre>
                  </Alert>
                ) : (
                  <Alert severity="error">
                    ❌ Test failed
                    <pre style={{ fontSize: '12px', marginTop: '8px' }}>
                      {JSON.stringify(result.error, null, 2)}
                    </pre>
                  </Alert>
                )}
              </CardContent>
            </Card>
          ))}
        </Box>
      )}
    </Box>
  );
};

export default ApiTest; 