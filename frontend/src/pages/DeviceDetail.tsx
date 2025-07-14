import React from 'react';
import { Box, Typography, Card, CardContent, TextField, Button } from '@mui/material';
import { useState } from 'react';
import { deviceAPI } from '../services/api';
import { useEffect } from 'react';
import { useParams } from 'react-router-dom';

const DeviceDetail: React.FC = () => {
  const { deviceId } = useParams<{ deviceId: string }>();
  const [device, setDevice] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    const fetchDevice = async () => {
      setLoading(true);
      try {
        const res = await deviceAPI.getDevice(Number(deviceId));
        setDevice(res.data);
      } catch (e) {
        setMessage('Failed to load device.');
      } finally {
        setLoading(false);
      }
    };
    fetchDevice();
  }, [deviceId]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setDevice({ ...device, [e.target.name]: e.target.value });
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage('');
    try {
      await deviceAPI.updateDevice(device.id, {
        ssh_username: device.ssh_username,
        ssh_password: device.ssh_password,
      });
      setMessage('SSH credentials updated!');
    } catch (e) {
      setMessage('Failed to update credentials.');
    } finally {
      setSaving(false);
    }
  };

  if (loading || !device) {
    return <Typography>Loading device...</Typography>;
  }

  return (
    <Box>
      <Typography variant="h4" component="h1" sx={{ mb: 3 }}>
        Device Details
      </Typography>
      <Card>
        <CardContent>
          <Typography variant="body1" sx={{ mb: 2 }}>
            SSH Credential Management
          </Typography>
          <TextField
            label="SSH Username"
            name="ssh_username"
            value={device.ssh_username || ''}
            onChange={handleChange}
            sx={{ mb: 2, mr: 2 }}
          />
          <TextField
            label="SSH Password"
            name="ssh_password"
            type="password"
            value={device.ssh_password || ''}
            onChange={handleChange}
            sx={{ mb: 2 }}
          />
          <Box sx={{ mt: 2 }}>
            <Button variant="contained" onClick={handleSave} disabled={saving}>
              {saving ? 'Saving...' : 'Save SSH Credentials'}
            </Button>
          </Box>
          {message && <Typography sx={{ mt: 2 }}>{message}</Typography>}
        </CardContent>
      </Card>
    </Box>
  );
};

export default DeviceDetail;
export {} 