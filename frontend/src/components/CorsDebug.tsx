import React, { useState } from 'react';
import { Box, Button, Typography, Card, CardContent, Alert, TextField } from '@mui/material';

const CorsDebug: React.FC = () => {
  const [testUrl, setTestUrl] = useState('http://localhost:8001/api/health');
  const [results, setResults] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const testCors = async () => {
    setLoading(true);
    setResults('');

    try {
      console.log(`Testing CORS for: ${testUrl}`);
      
      const response = await fetch(testUrl, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      console.log('Response status:', response.status);
      console.log('Response headers:', response.headers);

      if (response.ok) {
        const data = await response.json();
        setResults(`✅ SUCCESS\nStatus: ${response.status}\nData: ${JSON.stringify(data, null, 2)}`);
      } else {
        setResults(`❌ HTTP ERROR\nStatus: ${response.status}\nStatus Text: ${response.statusText}`);
      }
    } catch (error) {
      console.error('CORS test error:', error);
      setResults(`❌ CORS ERROR\n${error}`);
    } finally {
      setLoading(false);
    }
  };

  const testWithCredentials = async () => {
    setLoading(true);
    setResults('');

    try {
      console.log(`Testing CORS with credentials for: ${testUrl}`);
      
      const response = await fetch(testUrl, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      console.log('Response status:', response.status);
      console.log('Response headers:', response.headers);

      if (response.ok) {
        const data = await response.json();
        setResults(`✅ SUCCESS (with credentials)\nStatus: ${response.status}\nData: ${JSON.stringify(data, null, 2)}`);
      } else {
        setResults(`❌ HTTP ERROR (with credentials)\nStatus: ${response.status}\nStatus Text: ${response.statusText}`);
      }
    } catch (error) {
      console.error('CORS test error:', error);
      setResults(`❌ CORS ERROR (with credentials)\n${error}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="h5" gutterBottom>
        CORS Debug Tool
      </Typography>
      
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <TextField
            fullWidth
            label="API URL to test"
            value={testUrl}
            onChange={(e) => setTestUrl(e.target.value)}
            sx={{ mb: 2 }}
          />
          
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Button 
              variant="contained" 
              onClick={testCors} 
              disabled={loading}
            >
              Test CORS
            </Button>
            
            <Button 
              variant="outlined" 
              onClick={testWithCredentials} 
              disabled={loading}
            >
              Test with Credentials
            </Button>
          </Box>
        </CardContent>
      </Card>

      {results && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Test Results
            </Typography>
            <pre style={{ 
              backgroundColor: '#f5f5f5', 
              padding: '10px', 
              borderRadius: '4px',
              fontSize: '12px',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word'
            }}>
              {results}
            </pre>
          </CardContent>
        </Card>
      )}

      <Card sx={{ mt: 2 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Quick Tests
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Button 
              size="small" 
              variant="outlined"
              onClick={() => setTestUrl('http://localhost:8001/api/health')}
            >
              Health Check
            </Button>
            <Button 
              size="small" 
              variant="outlined"
              onClick={() => setTestUrl('http://localhost:8001/api/cors-test')}
            >
              CORS Test
            </Button>
            <Button 
              size="small" 
              variant="outlined"
              onClick={() => setTestUrl('http://localhost:8001/api/devices')}
            >
              Devices
            </Button>
            <Button 
              size="small" 
              variant="outlined"
              onClick={() => setTestUrl('http://localhost:8001/api/scan/status')}
            >
              Scan Status
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default CorsDebug; 