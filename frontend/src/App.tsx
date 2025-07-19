import React, { Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Layout from './components/Layout';

// Lazy load pages for code-splitting
const Dashboard = lazy(() => import('./pages/Dashboard'));
const DeviceList = lazy(() => import('./pages/DeviceList'));
const ManagedDevices = lazy(() => import('./pages/ManagedDevices'));
const DeviceDetail = lazy(() => import('./pages/DeviceDetail'));
const NetworkScan = lazy(() => import('./pages/NetworkScan'));
const SecurityAnalysis = lazy(() => import('./pages/SecurityAnalysis'));
const AIRecommendations = lazy(() => import('./pages/AIRecommendations'));
const Settings = lazy(() => import('./pages/Settings'));

// Create an enhanced dark theme with beautiful colors
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00d4aa',
      light: '#4dffdb',
      dark: '#00a382',
      contrastText: '#000000',
    },
    secondary: {
      main: '#ff6b35',
      light: '#ff9a6b',
      dark: '#c53d13',
      contrastText: '#ffffff',
    },
    success: {
      main: '#4caf50',
      light: '#81c784',
      dark: '#388e3c',
    },
    warning: {
      main: '#ff9800',
      light: '#ffb74d',
      dark: '#f57c00',
    },
    error: {
      main: '#f44336',
      light: '#ef5350',
      dark: '#d32f2f',
    },
    info: {
      main: '#2196f3',
      light: '#64b5f6',
      dark: '#1976d2',
    },
    background: {
      default: '#0a0e1a',
      paper: '#1a1f2e',
    },
    text: {
      primary: '#ffffff',
      secondary: 'rgba(255, 255, 255, 0.7)',
    },
  },
  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'linear-gradient(135deg, #1a1f2e 0%, #1e2332 100%)',
          border: '1px solid rgba(0, 212, 170, 0.1)',
          borderRadius: '12px',
          transition: 'all 0.3s ease-in-out',
          '&:hover': {
            transform: 'translateY(-2px)',
            boxShadow: '0 8px 25px rgba(0, 212, 170, 0.15)',
            border: '1px solid rgba(0, 212, 170, 0.3)',
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: '8px',
          textTransform: 'none',
          fontWeight: 600,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: '6px',
          fontWeight: 500,
        },
      },
    },
  },
});

// Create a query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <Router>
          <Layout>
            <Suspense fallback={<div>Loading...</div>}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/devices" element={<DeviceList />} />
                <Route path="/managed-devices" element={<ManagedDevices />} />
                <Route path="/devices/:id" element={<DeviceDetail />} />
                <Route path="/scan" element={<NetworkScan />} />
                <Route path="/security" element={<SecurityAnalysis />} />
                <Route
                  path="/ai-recommendations"
                  element={<AIRecommendations />}
                />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </Suspense>
          </Layout>
        </Router>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
