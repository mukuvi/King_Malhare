import { useEffect, useState } from "react";
import { WifiOff } from "lucide-react";

export function OfflineBanner() {
  const [offline, setOffline] = useState(typeof navigator !== "undefined" && !navigator.onLine);

  useEffect(() => {
    const online = () => setOffline(false);
    const offlineHandler = () => setOffline(true);
    window.addEventListener("online", online);
    window.addEventListener("offline", offlineHandler);
    return () => {
      window.removeEventListener("online", online);
      window.removeEventListener("offline", offlineHandler);
    };
  }, []);

  if (!offline) return null;

  return (
    <div className="flex items-center gap-2 border-b border-amber-500/25 bg-amber-500/10 px-4 py-2 text-[11.5px] text-amber-700">
      <WifiOff className="h-3.5 w-3.5 shrink-0" />
      You are offline. The cached console can open, but local assessments require the API and scanner worker to be running.
    </div>
  );
}
