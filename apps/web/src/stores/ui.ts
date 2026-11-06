import { create } from "zustand";

interface UIState {
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  toggleSidebar: () => void;
  commandOpen: boolean;
  setCommandOpen: (open: boolean) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: false,
  setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  commandOpen: false,
  setCommandOpen: (commandOpen) => set({ commandOpen }),
}));

interface AuthState {
  permissions: string[];
  role: string;
  orgName: string;
  setAuth: (permissions: string[], role: string, orgName: string) => void;
  can: (permission: string) => boolean;
  clear: () => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  permissions: [],
  role: "",
  orgName: "",
  setAuth: (permissions, role, orgName) => set({ permissions, role, orgName }),
  can: (permission) => get().permissions.includes(permission),
  clear: () => set({ permissions: [], role: "", orgName: "" }),
}));
