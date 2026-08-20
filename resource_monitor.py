"""
ResourceMonitor: background sampler for host resource usage.
Provides current snapshot and rolling-window averages (e.g., last 5 minutes), plus top-process sampling.
"""
import threading
import time
from collections import deque
from typing import Dict, Any, List

try:
    import psutil
except Exception:
    psutil = None

DEFAULT_INTERVAL = 10  # seconds between samples
DEFAULT_WINDOW = 300   # 5 minutes in seconds

class ResourceMonitor:
    def __init__(self, interval: int = DEFAULT_INTERVAL, max_window: int = DEFAULT_WINDOW):
        self.interval = interval
        # max samples based on window and interval; add a little headroom
        self.maxlen = max(1, int(max_window // interval) + 5)
        self.samples = deque(maxlen=self.maxlen)  # each sample: dict {ts, cpu, mem, procs}
        self.lock = threading.Lock()
        self._running = False
        self._thread = None

    def _prime_process_counters(self):
        if psutil is None:
            return
        # call once to prime per-process cpu counters
        for p in psutil.process_iter(attrs=['pid','name']):
            try:
                p.cpu_percent(None)
            except Exception:
                continue

    def _sample(self) -> Dict[str, Any] | None:
        if psutil is None:
            return None
        try:
            ts = time.time()
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            procs = []
            for p in psutil.process_iter(attrs=['pid','name']):
                try:
                    pid = p.info.get('pid')
                    name = p.info.get('name')
                    # get instantaneous values relative to last call
                    cpu_p = p.cpu_percent(None)
                    mem_p = p.memory_percent()
                    procs.append({'pid': pid, 'name': name, 'cpu_percent': float(cpu_p or 0.0), 'memory_percent': float(mem_p or 0.0)})
                except Exception:
                    continue
            procs_sorted = sorted(procs, key=lambda x: x['cpu_percent'], reverse=True)[:20]
            return {'ts': ts, 'cpu': float(cpu), 'mem': float(mem), 'procs': procs_sorted}
        except Exception:
            return None

    def _run(self):
        # Prime cpu counters for system and processes
        try:
            if psutil is not None:
                psutil.cpu_percent(interval=0.1)
                self._prime_process_counters()
        except Exception:
            pass
        while self._running:
            s = self._sample()
            if s is not None:
                with self.lock:
                    self.samples.append(s)
            time.sleep(self.interval)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=1)

    def get_current(self) -> Dict[str, Any]:
        """Return latest sample including process list; fallback to immediate read."""
        with self.lock:
            if self.samples:
                s = self.samples[-1]
                return {'timestamp': s['ts'], 'cpu_percent': s['cpu'], 'memory_percent': s['mem'], 'procs': s.get('procs', [])}
        s = self._sample()
        if s:
            return {'timestamp': s['ts'], 'cpu_percent': s['cpu'], 'memory_percent': s['mem'], 'procs': s.get('procs', [])}
        return {'error': 'psutil unavailable'}

    def get_avg(self, window_seconds: int = DEFAULT_WINDOW) -> Dict[str, Any]:
        """Compute average CPU/memory and per-process averages over the window_seconds."""
        cutoff = time.time() - window_seconds
        with self.lock:
            relevant = [s for s in self.samples if s['ts'] >= cutoff]
        if not relevant:
            cur = self.get_current()
            if 'error' in cur:
                return {'error': 'no samples and psutil unavailable'}
            return {'avg_window_seconds': window_seconds, 'cpu_percent': cur.get('cpu_percent'), 'memory_percent': cur.get('memory_percent'), 'samples': 1, 'procs': cur.get('procs', [])}

        cpu_avg = sum(s['cpu'] for s in relevant) / len(relevant)
        mem_avg = sum(s['mem'] for s in relevant) / len(relevant)

        # aggregate per-process averages across the window
        proc_map: Dict[tuple, Dict[str, Any]] = {}
        for s in relevant:
            for p in s.get('procs', []):
                key = (p.get('pid'), p.get('name'))
                entry = proc_map.setdefault(key, {'pid': p.get('pid'), 'name': p.get('name'), 'cpu_sum': 0.0, 'mem_sum': 0.0, 'count': 0})
                entry['cpu_sum'] += p.get('cpu_percent', 0.0)
                entry['mem_sum'] += p.get('memory_percent', 0.0)
                entry['count'] += 1
        procs_avg: List[Dict[str, Any]] = []
        for (pid, name), v in proc_map.items():
            procs_avg.append({'pid': pid, 'name': name, 'cpu_percent': round(v['cpu_sum'] / v['count'], 2), 'memory_percent': round(v['mem_sum'] / v['count'], 2), 'samples': v['count']})
        procs_sorted = sorted(procs_avg, key=lambda x: x['cpu_percent'], reverse=True)[:20]

        return {'avg_window_seconds': window_seconds, 'cpu_percent': round(cpu_avg, 2), 'memory_percent': round(mem_avg, 2), 'samples': len(relevant), 'procs': procs_sorted}


# Singleton monitor instance (interval and window configurable via env)
import os
_interval = int(os.getenv('MONITOR_INTERVAL', str(DEFAULT_INTERVAL)))
_window = int(os.getenv('MONITOR_WINDOW', str(DEFAULT_WINDOW)))
monitor = ResourceMonitor(interval=_interval, max_window=_window)

if __name__ == '__main__':
    monitor.start()
    try:
        while True:
            print('current:', monitor.get_current())
            print('5min avg:', monitor.get_avg(300))
            time.sleep(5)
    except KeyboardInterrupt:
        monitor.stop()
