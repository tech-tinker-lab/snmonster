import React from 'react';
import { Card, Typography, Chip, Button } from '@mui/material';

export type Device = {
  id: number;
  hostname?: string;
  ip_address: string;
  device_type: string;
  operating_system: string;
  status: string;
  ai_risk_score: number;
  category?: string;
  mac_address?: string;
  last_seen?: string;
  ssh_username?: string;
};

export type DeviceCardProps = {
  device: Device;
  selected: boolean;
  onSelect: () => void;
  onSetSSH: () => void;
};

const DeviceCard: React.FC<DeviceCardProps> = ({ device, selected, onSelect, onSetSSH }) => {
  return (
    <Card
      sx={{ p: 2, border: selected ? '2px solid #1976d2' : '1px solid #e0e0e0', cursor: 'pointer', position: 'relative' }}
      onClick={onSelect}
    >
      <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{device.hostname || device.ip_address}</Typography>
      <Typography variant="body2" sx={{ color: '#64748b', fontSize: '0.8rem' }}>{device.ip_address} • {device.device_type}</Typography>
      <Typography variant="body2" sx={{ color: '#64748b', fontSize: '0.8rem' }}>{device.operating_system}</Typography>
      <Chip label={device.status} color={device.status.toLowerCase() === 'online' ? 'success' : 'default'} size="small" sx={{ mt: 1 }} />
      <Chip label={`Risk: ${device.ai_risk_score}`} color={device.ai_risk_score >= 8 ? 'error' : device.ai_risk_score >= 6 ? 'warning' : 'success'} size="small" sx={{ mt: 1, ml: 1 }} />
      <Button size="small" sx={{ mt: 2 }} onClick={e => { e.stopPropagation(); onSetSSH(); }}>Set SSH</Button>
    </Card>
  );
};

export default DeviceCard;
