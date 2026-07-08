import time
import threading
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass
from ..core.types import FiveTuple, Connection, ConnectionState, AppType, PacketAction, app_type_to_string

@dataclass
class TrackerStats:
    active_connections: int
    total_connections_seen: int
    classified_connections: int
    blocked_connections: int

class ConnectionTracker:
    def __init__(self, fp_id: int, max_connections: int = 100000):
        self.fp_id = fp_id
        self.max_connections = max_connections
        self.connections: Dict[FiveTuple, Connection] = {}
        
        # Stats
        self.total_seen = 0
        self.classified_count = 0
        self.blocked_count = 0

    def get_or_create_connection(self, tuple_val: FiveTuple) -> Connection:
        """Get an existing connection or create a new one. Handles eviction if table is full."""
        # Try finding native tuple
        if tuple_val in self.connections:
            return self.connections[tuple_val]
            
        # Try finding reverse tuple
        rev_tuple = tuple_val.reverse()
        if rev_tuple in self.connections:
            return self.connections[rev_tuple]

        # Check if we need to evict the oldest connection
        if len(self.connections) >= self.max_connections:
            self._evict_oldest()

        # Create new connection
        conn = Connection(
            tuple=tuple_val,
            state=ConnectionState.NEW,
            first_seen=time.time(),
            last_seen=time.time()
        )
        self.connections[tuple_val] = conn
        self.total_seen += 1
        return conn

    def get_connection(self, tuple_val: FiveTuple) -> Optional[Connection]:
        """Get an existing connection (native or reverse) or return None."""
        if tuple_val in self.connections:
            return self.connections[tuple_val]
            
        rev_tuple = tuple_val.reverse()
        if rev_tuple in self.connections:
            return self.connections[rev_tuple]
            
        return None

    def update_connection(self, conn: Connection, packet_size: int, is_outbound: bool) -> None:
        """Update last seen timestamp and bytes/packets counters."""
        conn.last_seen = time.time()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size

    def classify_connection(self, conn: Connection, app: AppType, sni: str) -> None:
        """Mark connection state as classified and store app type and SNI."""
        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni = sni
            conn.state = ConnectionState.CLASSIFIED
            self.classified_count += 1

    def block_connection(self, conn: Connection) -> None:
        """Mark connection state as blocked and action as DROP."""
        if conn.state != ConnectionState.BLOCKED:
            conn.state = ConnectionState.BLOCKED
            conn.action = PacketAction.DROP
            self.blocked_count += 1

    def close_connection(self, tuple_val: FiveTuple) -> None:
        """Set connection state to CLOSED."""
        conn = self.get_connection(tuple_val)
        if conn:
            conn.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        """Remove connections that have timed out or are closed."""
        now = time.time()
        removed = 0
        
        # We need to iterate over keys to safely delete while iterating
        keys_to_remove = []
        for tuple_val, conn in self.connections.items():
            age = now - conn.last_seen
            if age > timeout_seconds or conn.state == ConnectionState.CLOSED:
                keys_to_remove.append(tuple_val)
                
        for key in keys_to_remove:
            del self.connections[key]
            removed += 1
            
        return removed

    def get_all_connections(self) -> List[Connection]:
        """Return a list of all connections."""
        return list(self.connections.values())

    def get_active_count(self) -> int:
        """Return the number of active connections."""
        return len(self.connections)

    def get_stats(self) -> TrackerStats:
        """Return stats about this tracker."""
        return TrackerStats(
            active_connections=len(self.connections),
            total_connections_seen=self.total_seen,
            classified_connections=self.classified_count,
            blocked_connections=self.blocked_count
        )

    def clear(self) -> None:
        """Clear all tracked connections."""
        self.connections.clear()

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        """Iterate over all connections and execute the callback."""
        for conn in self.connections.values():
            callback(conn)

    def _evict_oldest(self) -> None:
        """Evict the oldest connection based on last_seen timestamp."""
        if not self.connections:
            return
            
        oldest_tuple = None
        oldest_time = float('inf')
        
        for tuple_val, conn in self.connections.items():
            if conn.last_seen < oldest_time:
                oldest_time = conn.last_seen
                oldest_tuple = tuple_val
                
        if oldest_tuple:
            del self.connections[oldest_tuple]


class GlobalConnectionTable:
    def __init__(self, num_fps: int):
        self.trackers: List[Optional[ConnectionTracker]] = [None] * num_fps
        self._lock = threading.Lock()

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        """Register a fast path thread tracker."""
        with self._lock:
            if fp_id < len(self.trackers):
                self.trackers[fp_id] = tracker

    def get_global_stats(self) -> dict:
        """Aggregate statistics and application distributions across all trackers."""
        with self._lock:
            total_active_connections = 0
            total_connections_seen = 0
            app_distribution: Dict[AppType, int] = {}
            domain_counts: Dict[str, int] = {}
            
            for tracker in self.trackers:
                if not tracker:
                    continue
                stats = tracker.get_stats()
                total_active_connections += stats.active_connections
                total_connections_seen += stats.total_connections_seen
                
                # Aggregate app and domain stats
                def collect(conn: Connection):
                    app_distribution[conn.app_type] = app_distribution.get(conn.app_type, 0) + 1
                    if conn.sni:
                        domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1
                        
                tracker.for_each(collect)
                
            # Sort domains to get top 20
            sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
            top_domains = sorted_domains[:20]
            
            return {
                "total_active_connections": total_active_connections,
                "total_connections_seen": total_connections_seen,
                "app_distribution": app_distribution,
                "top_domains": top_domains
            }

    def generate_report(self) -> str:
        """Generate a formatted C++ style connection report."""
        stats = self.get_global_stats()
        
        report = []
        report.append("\n╔══════════════════════════════════════════════════════════════╗")
        report.append("║               CONNECTION STATISTICS REPORT                    ║")
        report.append("╠══════════════════════════════════════════════════════════════╣")
        report.append(f"║ Active Connections:     {stats['total_active_connections']:<10}                          ║")
        report.append(f"║ Total Connections Seen: {stats['total_connections_seen']:<10}                          ║")
        report.append("╠══════════════════════════════════════════════════════════════╣")
        report.append("║                    APPLICATION BREAKDOWN                      ║")
        report.append("╠══════════════════════════════════════════════════════════════╣")
        
        app_dist = stats["app_distribution"]
        total_apps = sum(app_dist.values())
        
        sorted_apps = sorted(app_dist.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total_apps) if total_apps > 0 else 0.0
            app_str = app_type_to_string(app)
            report.append(f"║ {app_str:<20} {count:>10} ({pct:>5.1f}%)           ║")
            
        if stats["top_domains"]:
            report.append("╠══════════════════════════════════════════════════════════════╣")
            report.append("║                      TOP DOMAINS                             ║")
            report.append("╠══════════════════════════════════════════════════════════════╣")
            for domain, count in stats["top_domains"]:
                disp_domain = domain
                if len(disp_domain) > 35:
                    disp_domain = disp_domain[:32] + "..."
                report.append(f"║ {disp_domain:<40} {count:>10}           ║")
                
        report.append("╚══════════════════════════════════════════════════════════════╝\n")
        return "\n".join(report)
