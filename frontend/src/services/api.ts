import axios from 'axios';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8001',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

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
  // Get all devices
  getDevices: () => api.get('/api/devices'),
  
  // Get specific device
  getDevice: (id: number) => api.get(`/api/devices/${id}`),
  
  // Device actions
  pingDevice: (id: number) => api.post(`/api/devices/${id}/ping`),
  scanDevicePorts: (id: number) => api.post(`/api/devices/${id}/scan-ports`),
  securityScanDevice: (id: number) => api.post(`/api/devices/${id}/security-scan`),
  updateDevice: (id: number, data: any) => api.put(`/api/devices/${id}`, data),
  
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