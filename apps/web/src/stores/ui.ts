import { create } from "zustand";

export type ViewMode = "admin" | "user";

function initialViewMode(): ViewMode {
  try {
    return window.localStorage.getItem("km-view-mode") === "user" ? "user" : "admin";
  } catch {
    return "admin";
  }
}

interface UIState {
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  toggleSidebar: () => void;
  commandOpen: boolean;
  setCommandOpen: (open: boolean) => void;
  viewMode: ViewMode;
  setViewMode: (mode: ViewMode) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: false,
  setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  commandOpen: false,
  setCommandOpen: (commandOpen) => set({ commandOpen }),
  viewMode: initialViewMode(),
  setViewMode: (viewMode) => {
    try {
      window.localStorage.setItem("km-view-mode", viewMode);
    } catch {
      // Ignore storage failures.
    }
    set({ viewMode });
  },
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
