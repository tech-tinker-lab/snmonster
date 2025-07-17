import React, {
  useRef,
  useEffect,
  useState,
  useImperativeHandle,
  forwardRef,
} from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';

export interface XTermTerminalHandle {
  write: (data: string) => void;
  disconnect: () => void;
}

interface XTermTerminalProps {
  wsUrl: string;
  onStatus?: (status: string) => void;
  onError?: (error: string) => void;
  onData?: (data: string) => void;
  style?: React.CSSProperties;
  className?: string;
  height?: number | string;
  fontSize?: number;
}

const XTermTerminal = forwardRef<XTermTerminalHandle, XTermTerminalProps>(
  (
    {
      wsUrl,
      onStatus,
      onError,
      onData,
      style = {},
      className = '',
      height = 350,
      fontSize = 14,
    },
    ref
  ) => {
    const containerRef = useRef<HTMLDivElement | null>(null);
    const term = useRef<Terminal | null>(null);
    const fitAddon = useRef<FitAddon | null>(null);
    const wsRef = useRef<WebSocket | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const [error, setError] = useState<string | null>(null);
    // const [uploadingScripts, setUploadingScripts] = useState(false);
    const [uploadDone, setUploadDone] = useState(false);

    const disconnect = () => {
      console.log('Disconnecting terminal...');
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setIsConnected(false);
      if (term.current) {
        term.current.writeln('\r\n[Disconnected by user]');
      }
      if (onStatus) onStatus('disconnected');
    };

    useImperativeHandle(
      ref,
      () => ({
        write: (data: string) => {
          if (term.current && isConnected) {
            term.current.write(data);
            if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
              wsRef.current.send(data);
            }
          }
        },
        disconnect,
      }),
      [isConnected, disconnect]
    );

    useEffect(() => {
      let mounted = true;
      let ws: WebSocket | null = null;

      const initTerminal = () => {
        if (!containerRef.current || !mounted) return;

        try {
          console.log('Initializing terminal...');

          // Clean up existing terminal
          if (term.current) {
            term.current.dispose();
            term.current = null;
          }

          // Create new terminal with minimal options
          term.current = new Terminal({
            fontSize,
            theme: { background: '#1e1e1e' },
            cursorBlink: true,
            rows: 20,
            cols: 80,
          });

          fitAddon.current = new FitAddon();
          term.current.loadAddon(fitAddon.current);

          // Open terminal
          term.current.open(containerRef.current);

          // Simple fit with delay
          setTimeout(() => {
            if (mounted && term.current && fitAddon.current) {
              try {
                fitAddon.current.fit();
              } catch (e) {
                console.warn('Fit failed:', e);
              }
            }
          }, 100);

          // Set up WebSocket
          console.log('Connecting to WebSocket:', wsUrl);
          ws = new WebSocket(wsUrl);
          wsRef.current = ws;

          ws.onopen = () => {
            console.log('WebSocket connected!');
            if (mounted) {
              setIsConnected(true);
              setError(null);
              // setUploadingScripts(true);
              setUploadDone(false);
              if (onStatus) onStatus('connected');
              term.current?.writeln('[Connected]');
            }
          };

          ws.onmessage = (event) => {
            console.log('WebSocket message received:', event.data);
            if (!mounted || !term.current) return;

            try {
              const msg = JSON.parse(event.data);
              console.log('Parsed message:', msg);
              switch (msg.type) {
                case 'status':
                  console.log('Status message:', msg.status);
                  if (onStatus) onStatus(msg.status);
                  if (msg.status === 'connected') {
                    term.current.writeln('[Connected]');
                  }
                  break;
                case 'data': {
                  const data =
                    msg.encoding === 'base64' ? atob(msg.data) : msg.data;
                  // Detect script upload phase
                  // if (uploadingScripts && typeof data === 'string') {
                  //   if (
                  //     data.includes(
                  //       '✅ Automation scripts uploaded successfully!'
                  //     )
                  //   ) {
                  //     setUploadingScripts(false);
                  //     setUploadDone(true);
                  //   }
                  // }
                  console.log('Data received, length:', data.length);
                  term.current.write(data);
                  if (onData) onData(data);
                  break;
                }
                case 'error':
                  console.error('Error message:', msg.message);
                  if (onError) onError(msg.message);
                  term.current.writeln(`[Error: ${msg.message}]`);
                  break;
                default:
                  console.log('Unknown message type:', msg.type);
                  term.current.write(event.data);
                  if (onData) onData(event.data);
              }
            } catch (parseError) {
              console.log(
                'Failed to parse JSON, treating as raw data:',
                event.data
              );
              // Fallback to raw data
              term.current.write(event.data);
              if (onData) onData(event.data);
            }
          };

          ws.onclose = (event) => {
            console.log('WebSocket closed:', event.code, event.reason);
            if (mounted) {
              setIsConnected(false);
              if (onStatus) onStatus('disconnected');
              term.current?.writeln('\r\n[Disconnected]');
            }
          };

          ws.onerror = (event) => {
            console.error('WebSocket error:', event);
            if (mounted) {
              setError('Connection failed');
              if (onError) onError('Connection failed');
              term.current?.writeln('\r\n[Connection error]');
            }
          };

          // Handle user input
          term.current.onData((data) => {
            console.log('Terminal input:', data);
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(data);
            }
          });
        } catch (e) {
          console.error('Terminal init error:', e);
          setError('Failed to initialize terminal');
          if (onError) onError('Failed to initialize terminal');
        }
      };

      // Initialize after a short delay to ensure container is ready
      const timer = setTimeout(initTerminal, 50);

      return () => {
        console.log('Cleaning up terminal...');
        mounted = false;
        clearTimeout(timer);

        if (ws) {
          ws.close();
          wsRef.current = null;
        }

        if (term.current) {
          term.current.dispose();
          term.current = null;
        }

        fitAddon.current = null;
      };
    }, [wsUrl, fontSize, onStatus, onError, onData]);

    return (
      <div
        style={{ position: 'relative', width: '100%', height, ...style }}
        className={className}
      >
        {/* Disconnect button */}
        {isConnected && (
          <button
            onClick={disconnect}
            style={{
              position: 'absolute',
              top: '8px',
              right: '8px',
              zIndex: 10,
              background: '#dc3545',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              padding: '6px 12px',
              fontSize: '12px',
              cursor: 'pointer',
              fontWeight: 'bold',
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.background = '#c82333';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.background = '#dc3545';
            }}
          >
            Disconnect
          </button>
        )}

        {/* Uploading scripts indicator removed */}
        {/* Upload done indicator (optional, fades after a moment) */}
        {uploadDone && (
          <div
            style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              background: 'rgba(0,0,0,0.85)',
              color: '#00d4aa',
              padding: '18px 28px',
              borderRadius: '10px',
              zIndex: 20,
              fontWeight: 'bold',
              fontSize: 16,
              boxShadow: '0 4px 24px 0 rgba(0,0,0,0.25)',
            }}
          >
            <span role="img" aria-label="check">
              ✅
            </span>{' '}
            Automation scripts uploaded!
          </div>
        )}

        <div
          ref={containerRef}
          style={{
            width: '100%',
            height: '100%',
            background: '#1e1e1e',
            borderRadius: 4,
            padding: '8px',
          }}
        />
        {error && (
          <div
            style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              background: 'rgba(0,0,0,0.8)',
              color: 'white',
              padding: '16px',
              borderRadius: '8px',
              zIndex: 10,
            }}
          >
            {error}
          </div>
        )}
      </div>
    );
  }
);

export default XTermTerminal;
