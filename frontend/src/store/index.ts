import { create } from 'zustand';

// Example global state for devices and user settings
interface StoreDevice {
  id: number;
  name: string;
  status: string;
  [key: string]: any;
}

interface StoreState {
  devices: StoreDevice[];
  setDevices: (devices: StoreDevice[]) => void;
  selectedDevice: StoreDevice | null;
  setSelectedDevice: (device: StoreDevice | null) => void;
  userSettings: Record<string, any>;
  setUserSettings: (settings: Record<string, any>) => void;
}

export const useStore = create<StoreState>((set) => ({
  devices: [],
  setDevices: (devices) => set({ devices }),
  selectedDevice: null,
  setSelectedDevice: (device) => set({ selectedDevice: device }),
  userSettings: {},
  setUserSettings: (settings) => set({ userSettings: settings }),
}));
