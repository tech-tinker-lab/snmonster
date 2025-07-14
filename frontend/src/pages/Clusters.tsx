import React, { useMemo } from 'react';
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  Node,
  Edge,
  Connection,
  ReactFlowProvider,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Card, CardContent, Typography } from '@mui/material';
import { useQuery } from 'react-query';
import { deviceAPI } from '../services/api';

// Add Device interface for type safety
interface Device {
  id: number;
  ip_address: string;
  hostname: string;
  device_type: string;
  operating_system: string;
  status: string;
  last_seen: string;
  ai_risk_score: number;
  mac_address: string;
  open_ports?: string;
  vulnerabilities?: string;
}

const initialEdges: Edge[] = [];

const Clusters: React.FC = () => {
  // Fetch devices from backend
  const { data: devicesData } = useQuery('devices', async () => {
    const response = await deviceAPI.getDevices();
    return response.data;
  });
  const devices = devicesData?.devices || [];

  // Map devices to nodes
  const initialNodes: Node[] = useMemo(() =>
    devices.map((device: Device, idx: number) => ({
      id: device.id.toString(),
      type: 'default',
      position: { x: 100 + (idx % 5) * 180, y: 100 + Math.floor(idx / 5) * 120 },
      data: {
        label: `${device.hostname || device.ip_address} (${device.device_type})`,
      },
      style: { width: 150 },
    })),
    [devices]
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onConnect = (params: Edge | Connection) => setEdges((eds) => addEdge(params, eds));

  return (
    <Card sx={{ m: 3 }}>
      <CardContent>
        <Typography variant="h4" gutterBottom>Cluster & Topology Designer</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Drag devices, draw connections, and visually group machines. (Grouping/boxes coming soon)
        </Typography>
        <div style={{ height: 600, background: '#222', borderRadius: 8 }}>
          <ReactFlowProvider>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              fitView
            >
              <MiniMap />
              <Controls />
              <Background gap={16} color="#444" />
            </ReactFlow>
          </ReactFlowProvider>
        </div>
      </CardContent>
    </Card>
  );
};

export default Clusters; 