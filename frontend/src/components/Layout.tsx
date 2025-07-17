import React, { useState } from 'react';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  List,
  Typography,
  IconButton,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Badge,
  Chip,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  DevicesOther as DevicesIcon,
  Security as SecurityIcon,
  Psychology as PsychologyIcon,
  Settings as SettingsIcon,
  NetworkCheck as NetworkCheckIcon,
  Notifications as NotificationsIcon,
  Router as RouterIcon,
  AccountCircle as AccountCircleIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';

const drawerWidth = 240;

interface LayoutProps {
  children: React.ReactNode;
}

const menuItems = [
  {
    text: 'Dashboard',
    icon: <DashboardIcon />,
    path: '/',
    color: '#00d4aa',
    description: 'Network overview',
  },
  {
    text: 'Devices',
    icon: <DevicesIcon />,
    path: '/devices',
    color: '#2196f3',
    description: 'Manage devices',
  },
  {
    text: 'Network Scan',
    icon: <NetworkCheckIcon />,
    path: '/scan',
    color: '#ff9800',
    description: 'Discover devices',
  },
  {
    text: 'Security',
    icon: <SecurityIcon />,
    path: '/security',
    color: '#f44336',
    description: 'Security analysis',
  },
  {
    text: 'AI Insights',
    icon: <PsychologyIcon />,
    path: '/ai-recommendations',
    color: '#9c27b0',
    description: 'AI recommendations',
  },
  {
    text: 'Settings',
    icon: <SettingsIcon />,
    path: '/settings',
    color: '#607d8b',
    description: 'Configuration',
  },
];

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleNavigation = (path: string) => {
    navigate(path);
    setMobileOpen(false);
  };

  const drawer = (
    <Box
      sx={{
        background: 'linear-gradient(180deg, #1a1f2e 0%, #0a0e1a 100%)',
        height: '100%',
        borderRight: '1px solid rgba(0, 212, 170, 0.1)',
      }}
    >
      <Toolbar
        sx={{
          background: 'linear-gradient(135deg, #00d4aa 0%, #00a382 100%)',
          color: '#000',
          mb: 2,
          position: 'relative',
          overflow: 'hidden',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background:
              'url("data:image/svg+xml,%3Csvg width="60" height="60" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"%3E%3Cg fill="none" fill-rule="evenodd"%3E%3Cg fill="%23000" fill-opacity="0.05"%3E%3Ccircle cx="7" cy="7" r="1"/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")',
          },
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, zIndex: 1 }}>
          <RouterIcon sx={{ fontSize: 28, color: '#000' }} />
          <Box>
            <Typography
              variant="h6"
              component="div"
              sx={{
                color: '#000',
                fontWeight: 'bold',
                lineHeight: 1.2,
              }}
            >
              SNMonster
            </Typography>
            <Typography
              variant="caption"
              sx={{
                color: 'rgba(0,0,0,0.7)',
                fontSize: '0.7rem',
              }}
            >
              Network Admin
            </Typography>
          </Box>
        </Box>
      </Toolbar>

      <List sx={{ px: 1 }}>
        {menuItems.map((item) => {
          const isSelected = location.pathname === item.path;
          return (
            <ListItem key={item.text} disablePadding sx={{ mb: 0.5 }}>
              <ListItemButton
                selected={isSelected}
                onClick={() => handleNavigation(item.path)}
                sx={{
                  borderRadius: '8px',
                  mx: 1,
                  transition: 'all 0.3s ease',
                  position: 'relative',
                  overflow: 'hidden',
                  '&.Mui-selected': {
                    backgroundColor: alpha(item.color, 0.15),
                    border: `1px solid ${alpha(item.color, 0.3)}`,
                    '&:hover': {
                      backgroundColor: alpha(item.color, 0.25),
                    },
                    '&::before': {
                      content: '""',
                      position: 'absolute',
                      left: 0,
                      top: 0,
                      bottom: 0,
                      width: '3px',
                      backgroundColor: item.color,
                    },
                  },
                  '&:hover': {
                    backgroundColor: alpha(item.color, 0.1),
                    transform: 'translateX(4px)',
                  },
                }}
              >
                <ListItemIcon
                  sx={{
                    color: isSelected ? item.color : 'text.secondary',
                    minWidth: 40,
                    transition: 'color 0.3s ease',
                  }}
                >
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.text}
                  secondary={item.description}
                  sx={{
                    '& .MuiListItemText-primary': {
                      color: isSelected ? item.color : 'text.primary',
                      fontWeight: isSelected ? 600 : 400,
                      fontSize: '0.9rem',
                    },
                    '& .MuiListItemText-secondary': {
                      color: 'text.secondary',
                      fontSize: '0.75rem',
                    },
                  }}
                />
                {isSelected && (
                  <Box
                    sx={{
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      backgroundColor: item.color,
                      boxShadow: `0 0 8px ${item.color}`,
                    }}
                  />
                )}
              </ListItemButton>
            </ListItem>
          );
        })}
      </List>

      <Box sx={{ mt: 'auto', p: 2 }}>
        <Chip
          icon={<NotificationsIcon />}
          label="System Active"
          color="success"
          variant="outlined"
          size="small"
          sx={{
            width: '100%',
            justifyContent: 'flex-start',
            '& .MuiChip-icon': {
              color: 'success.main',
            },
          }}
        />
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          ml: { sm: `${drawerWidth}px` },
          background: 'linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%)',
          borderBottom: '1px solid rgba(0, 212, 170, 0.2)',
          backdropFilter: 'blur(10px)',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.3)',
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{
              mr: 2,
              display: { sm: 'none' },
              '&:hover': {
                backgroundColor: alpha('#00d4aa', 0.1),
              },
            }}
          >
            <MenuIcon />
          </IconButton>

          <Box
            sx={{ flexGrow: 1, display: 'flex', alignItems: 'center', gap: 2 }}
          >
            <Typography
              variant="h6"
              component="div"
              sx={{
                background: 'linear-gradient(45deg, #00d4aa, #4dffdb)',
                backgroundClip: 'text',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                fontWeight: 'bold',
              }}
            >
              AI-Powered Network Administration
            </Typography>
            <Chip
              icon={<RouterIcon sx={{ fontSize: 16 }} />}
              label="Live Monitoring"
              color="primary"
              size="small"
              variant="outlined"
              sx={{
                '& .MuiChip-icon': {
                  color: 'primary.main',
                },
              }}
            />
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Chip
              label="System Online"
              color="success"
              size="small"
              variant="filled"
              sx={{
                backgroundColor: alpha('#4caf50', 0.2),
                border: `1px solid ${alpha('#4caf50', 0.3)}`,
                '& .MuiChip-label': {
                  color: '#4caf50',
                  fontWeight: 600,
                },
              }}
            />

            <IconButton
              color="inherit"
              sx={{
                '&:hover': {
                  backgroundColor: alpha('#ff6b35', 0.1),
                },
              }}
            >
              <Badge
                badgeContent={3}
                color="error"
                sx={{
                  '& .MuiBadge-badge': {
                    backgroundColor: '#ff6b35',
                    color: '#fff',
                    fontWeight: 'bold',
                  },
                }}
              >
                <NotificationsIcon sx={{ color: '#ff6b35' }} />
              </Badge>
            </IconButton>

            <IconButton
              color="inherit"
              sx={{
                ml: 1,
                '&:hover': {
                  backgroundColor: alpha('#00d4aa', 0.1),
                },
              }}
            >
              <AccountCircleIcon sx={{ color: '#00d4aa', fontSize: 28 }} />
            </IconButton>
          </Box>
        </Toolbar>
      </AppBar>
      <Box
        component="nav"
        sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
      >
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true,
          }}
          sx={{
            display: { xs: 'block', sm: 'none' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
              backgroundColor: 'background.paper',
              borderRight: '1px solid #333',
            },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', sm: 'block' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
              backgroundColor: 'background.paper',
              borderRight: '1px solid #333',
            },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          mt: 8,
        }}
      >
        {children}
      </Box>
    </Box>
  );
};

export default Layout;
