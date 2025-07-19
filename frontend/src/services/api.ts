import axios from 'axios';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8004',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Helper function to get the WebSocket URL for the backend
export const getBackendWsUrl = () => {
  const backendUrl = process.env.REACT_APP_API_URL || 'http://localhost:8004';
  const url = new URL(backendUrl);
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${protocol}://${url.hostname}:${url.port}`;
};

// Request interceptor for logging
api.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('API Response Error:', error);
    return Promise.reject(error);
  }
);

// API endpoints
export const deviceAPI = {
  // Get all devices (unmanaged only)
  getDevices: () => api.get('/api/devices'),

  // Get managed devices
  getManagedDevices: () => api.get('/api/devices/managed'),

  // Get all devices (both managed and unmanaged)
  getAllDevices: () => api.get('/api/devices/all'),

  // Get specific device
  getDevice: (id: number) => api.get(`/api/devices/${id}`),

  // Device management
  markDevicesAsManaged: (deviceIds: number[]) =>
    api.post('/api/devices/mark-managed', deviceIds),
  unmarkDevicesAsManaged: (deviceIds: number[]) =>
    api.post('/api/devices/unmark-managed', deviceIds),

  // Bulk actions for managed devices
  setBulkPassword: (deviceIds: number[], password: string) =>
    api.post('/api/devices/bulk-set-password', {
      device_ids: deviceIds,
      password,
    }),
  installDocker: (deviceIds: number[]) =>
    api.post('/api/devices/bulk-install-docker', { device_ids: deviceIds }),
  installAnsible: (deviceIds: number[]) =>
    api.post('/api/devices/bulk-install-ansible', { device_ids: deviceIds }),
  runSecurityAudit: (deviceIds: number[]) =>
    api.post('/api/devices/bulk-security-audit', { device_ids: deviceIds }),
  getSecurityReports: (deviceIds: number[]) =>
    api.post('/api/devices/security-reports', { device_ids: deviceIds }),

  // System update actions
  runSystemUpdate: (deviceIds: number[]) =>
    api.post('/api/devices/bulk-system-update', { device_ids: deviceIds }),
  getSystemUpdateStatus: (deviceIds: number[]) =>
    api.post('/api/devices/system-update-status', { device_ids: deviceIds }),

  // Device actions
  pingDevice: (id: number) => api.post(`/api/devices/${id}/ping`),
  scanDevicePorts: (id: number) => api.post(`/api/devices/${id}/scan-ports`),
  securityScanDevice: (id: number) =>
    api.post(`/api/devices/${id}/security-scan`),
  updateDevice: (id: number, data: any) => api.put(`/api/devices/${id}`, data),

  // AI-powered patching
  aiPatchDevice: (id: number) => api.post(`/api/devices/${id}/ai-patch`),

  // Get scan status
  getScanStatus: () => api.get('/api/scan/status'),

  // Start network scan
  startScan: () => api.post('/api/scan/start'),

  // Stop network scan
  stopScan: () => api.post('/api/scan/stop'),
};

export const systemAPI = {
  // Get system health
  getHealth: () => api.get('/api/health'),

  // Get AI analysis
  getAnalysis: () => api.post('/api/ai/analyze'),

  // Get AI recommendations
  getRecommendations: () => api.post('/api/ai/recommendations'),
};

export default api;
