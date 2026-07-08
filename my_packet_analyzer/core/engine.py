import time
import threading
import logging
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field

from .types import FiveTuple, AppType, ConnectionState, PacketAction, Connection, PacketJob
from .queue import ThreadSafeQueue
from ..capture.pcap import PcapReader, PcapWriter, RawPacket
from ..parser.protocols import PacketParser, ParsedPacket, TCPFlags, Protocol, EtherType
from ..rules.manager import RuleManager, BlockReason
from ..tracker.flow import ConnectionTracker, GlobalConnectionTable

# Deterministic hash function for FiveTuple matching C++ logic and avoiding interpreter randomization
def hash_tuple(t: FiveTuple) -> int:
    h = 0
    # Combine fields exactly like C++ combining hash logic
    for val in (t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.protocol):
        h = (h ^ val) + 0x9e3779b9 + (h << 6) + (h >> 2)
        h &= 0xFFFFFFFF  # Keep as 32-bit unsigned int
    return h


# =============================================================================
# Load Balancer Thread
# =============================================================================
class LoadBalancer:
    def __init__(self, lb_id: int, fp_queues: List[ThreadSafeQueue[PacketJob]], fp_start_id: int):
        self.lb_id = lb_id
        self.fp_start_id = fp_start_id
        self.num_fps = len(fp_queues)
        self.fp_queues = fp_queues
        self.input_queue = ThreadSafeQueue[PacketJob](10000)
        
        # Stats
        self.packets_received = 0
        self.packets_dispatched = 0
        self.per_fp_counts = [0] * self.num_fps
        
        # Control
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self.run, name=f"LBThread-{self.lb_id}")
        self.thread.start()
        logging.info(f"[LB{self.lb_id}] Started (serving FP{self.fp_start_id}-FP{self.fp_start_id + self.num_fps - 1})")

    def stop(self) -> None:
        self.running = False
        self.input_queue.shutdown()
        if self.thread and self.thread.is_alive():
            self.thread.join()
        logging.info(f"[LB{self.lb_id}] Stopped")

    def run(self) -> None:
        while self.running:
            job = self.input_queue.pop_with_timeout(0.1)
            if job is None:
                continue
                
            self.packets_received += 1
            
            # Select target FP based on consistent hash
            fp_index = hash_tuple(job.tuple) % self.num_fps
            self.fp_queues[fp_index].push(job)
            
            self.packets_dispatched += 1
            self.per_fp_counts[fp_index] += 1


# =============================================================================
# Fast Path Processor Thread
# =============================================================================
class FastPathProcessor:
    def __init__(self, fp_id: int, rule_manager: Optional[RuleManager], output_callback: Callable[[PacketJob, PacketAction], None]):
        self.fp_id = fp_id
        self.input_queue = ThreadSafeQueue[PacketJob](10000)
        self.conn_tracker = ConnectionTracker(fp_id)
        self.rule_manager = rule_manager
        self.output_callback = output_callback
        
        # Stats
        self.packets_processed = 0
        self.packets_forwarded = 0
        self.packets_dropped = 0
        self.sni_extractions = 0
        self.classification_hits = 0
        
        # Control
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self.run, name=f"FPThread-{self.fp_id}")
        self.thread.start()
        logging.info(f"[FP{self.fp_id}] Started")

    def stop(self) -> None:
        self.running = False
        self.input_queue.shutdown()
        if self.thread and self.thread.is_alive():
            self.thread.join()
        logging.info(f"[FP{self.fp_id}] Stopped (processed {self.packets_processed} packets)")

    def run(self) -> None:
        while self.running:
            job = self.input_queue.pop_with_timeout(0.1)
            if job is None:
                # Idle time: cleanup stale connections
                self.conn_tracker.cleanup_stale(300.0)
                continue
                
            self.packets_processed += 1
            action = self.process_packet(job)
            
            # Output handler
            self.output_callback(job, action)
            
            if action == PacketAction.DROP:
                self.packets_dropped += 1
            else:
                self.packets_forwarded += 1

    def process_packet(self, job: PacketJob) -> PacketAction:
        conn = self.conn_tracker.get_or_create_connection(job.tuple)
        
        # Update flow stats
        is_outbound = True  # Default model assumes outbound traffic from user
        self.conn_tracker.update_connection(conn, len(job.data), is_outbound)
        
        # Update TCP state
        if job.tuple.protocol == Protocol.TCP:
            self.update_tcp_state(conn, job.tcp_flags)
            
        # If already blocked, drop immediately
        if conn.state == ConnectionState.BLOCKED:
            return PacketAction.DROP
            
        # If not classified yet, try payload inspection
        if conn.state != ConnectionState.CLASSIFIED and job.payload_length > 0:
            self.inspect_payload(job, conn)
            
        # Check rules
        return self.check_rules(job, conn)

    def inspect_payload(self, job: PacketJob, conn: Connection) -> None:
        from ..dpi.extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor, QUICSNIExtractor
        
        payload = job.data[job.payload_offset : job.payload_offset + job.payload_length]
        
        # 1. TLS SNI
        if job.tuple.dst_port == 443 or len(payload) >= 50:
            sni = SNIExtractor.extract(payload)
            if sni:
                self.sni_extractions += 1
                from .types import sni_to_app_type
                app = sni_to_app_type(sni)
                self.conn_tracker.classify_connection(conn, app, sni)
                if app != AppType.UNKNOWN and app != AppType.HTTPS:
                    self.classification_hits += 1
                return

        # 2. HTTP Host
        if job.tuple.dst_port == 80:
            host = HTTPHostExtractor.extract(payload)
            if host:
                from .types import sni_to_app_type
                app = sni_to_app_type(host)
                self.conn_tracker.classify_connection(conn, app, host)
                if app != AppType.UNKNOWN and app != AppType.HTTP:
                    self.classification_hits += 1
                return

        # 3. DNS (Port 53)
        if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
            domain = DNSExtractor.extract_query(payload)
            if domain:
                self.conn_tracker.classify_connection(conn, AppType.DNS, domain)
                return

        # 4. QUIC (HTTPS over UDP fallback check)
        if job.tuple.dst_port == 443 and job.tuple.protocol == Protocol.UDP:
            sni = QUICSNIExtractor.extract(payload)
            if sni:
                self.sni_extractions += 1
                from .types import sni_to_app_type
                app = sni_to_app_type(sni)
                self.conn_tracker.classify_connection(conn, app, sni)
                return

        # Fallback port-based classification
        if job.tuple.dst_port == 80:
            self.conn_tracker.classify_connection(conn, AppType.HTTP, "")
        elif job.tuple.dst_port == 443:
            self.conn_tracker.classify_connection(conn, AppType.HTTPS, "")

    def check_rules(self, job: PacketJob, conn: Connection) -> PacketAction:
        if not self.rule_manager:
            return PacketAction.FORWARD
            
        reason = self.rule_manager.should_block(
            job.tuple.src_ip,
            job.tuple.dst_port,
            conn.app_type,
            conn.sni
        )
        
        if reason:
            msg = f"[FP{self.fp_id}] BLOCKED packet: {reason.type} {reason.detail}"
            logging.info(msg)
            self.conn_tracker.block_connection(conn)
            return PacketAction.DROP
            
        return PacketAction.FORWARD

    def update_tcp_state(self, conn: Connection, flags: int) -> None:
        if flags & TCPFlags.SYN:
            if flags & TCPFlags.ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True
                
        if conn.syn_seen and conn.syn_ack_seen and (flags & TCPFlags.ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED
                
        if flags & TCPFlags.FIN:
            conn.fin_seen = True
            
        if flags & TCPFlags.RST:
            conn.state = ConnectionState.CLOSED
            
        if conn.fin_seen and (flags & TCPFlags.ACK):
            conn.state = ConnectionState.CLOSED


# =============================================================================
# Multi-threaded DPI Engine (DPIEngine)
# =============================================================================
class DPIEngine:
    @dataclass
    class Config:
        num_load_balancers: int = 2
        fps_per_lb: int = 2
        queue_size: int = 10000
        rules_file: Optional[str] = None
        verbose: bool = False

    def __init__(self, config: Config):
        self.config = config
        
        # Statistics (matching atomic layout in C++)
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded_packets = 0
        self.dropped_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.stats_lock = threading.Lock()
        
        self.rule_manager = RuleManager()
        self.global_conn_table: Optional[GlobalConnectionTable] = None
        
        # Workers
        self.lbs: List[LoadBalancer] = []
        self.fps: List[FastPathProcessor] = []
        self.output_queue = ThreadSafeQueue[PacketJob](10000)
        
        # Control
        self.running = False
        self.reader_thread: Optional[threading.Thread] = None
        self.writer_thread: Optional[threading.Thread] = None
        self.output_writer: Optional[PcapWriter] = None

    def initialize(self) -> bool:
        if self.config.rules_file:
            self.rule_manager.load_rules(self.config.rules_file)
            
        total_fps = self.config.num_load_balancers * self.config.fps_per_lb
        self.global_conn_table = GlobalConnectionTable(total_fps)
        
        # Create FPs
        self.fps = []
        for i in range(total_fps):
            fp = FastPathProcessor(i, self.rule_manager, self.handle_output)
            self.fps.append(fp)
            self.global_conn_table.register_tracker(i, fp.conn_tracker)
            
        # Create LBs
        self.lbs = []
        for lb_id in range(self.config.num_load_balancers):
            fp_start = lb_id * self.config.fps_per_lb
            lb_fp_queues = [self.fps[fp_start + j].input_queue for j in range(self.config.fps_per_lb)]
            lb = LoadBalancer(lb_id, lb_fp_queues, fp_start)
            self.lbs.append(lb)
            
        print("\n"
              "╔══════════════════════════════════════════════════════════════╗\n"
              "║              DPI ENGINE v2.0 (Multi-threaded)                 ║\n"
              "╠══════════════════════════════════════════════════════════════╣\n"
              f"║ Load Balancers: {self.config.num_load_balancers:<2}    FPs per LB: {self.config.fps_per_lb:<2}    Total FPs: {total_fps:<2}     ║\n"
              "╚══════════════════════════════════════════════════════════════╝\n")
        return True

    def start(self) -> None:
        self.running = True
        
        # Start Writer
        self.writer_thread = threading.Thread(target=self.writer_thread_func, name="WriterThread")
        self.writer_thread.start()
        
        # Start Workers
        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()
            
        logging.info("[DPIEngine] All threads started")

    def stop(self) -> None:
        self.running = False
        
        # Stop LBs first (they feed FPs)
        for lb in self.lbs:
            lb.stop()
            
        # Stop FPs
        for fp in self.fps:
            fp.stop()
            
        # Stop Writer
        self.output_queue.shutdown()
        if self.writer_thread and self.writer_thread.is_alive():
            self.writer_thread.join()
            
        logging.info("[DPIEngine] All threads stopped")

    def process_file(self, input_file: str, output_file: str) -> bool:
        if not self.global_conn_table:
            self.initialize()
            
        self.output_writer = PcapWriter()
        
        # Open PCAP file
        reader = PcapReader()
        if not reader.open(input_file):
            return False
            
        if not self.output_writer.open(output_file, reader.get_global_header_dict()):
            reader.close()
            return False
            
        self.start()
        
        # Start Reader Thread
        self.reader_thread = threading.Thread(
            target=self.reader_thread_func, args=(reader,), name="ReaderThread"
        )
        self.reader_thread.start()
        
        # Wait for Reader Thread to complete
        self.reader_thread.join()
        
        # Wait for queues to drain
        time.sleep(0.5)
        
        self.stop()
        self.output_writer.close()
        
        # Print final report
        self.print_report()
        return True

    def reader_thread_func(self, reader: PcapReader) -> None:
        logging.info("Processing packets...")
        packet_id = 0
        
        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break
                
            parsed = PacketParser.parse(raw)
            if parsed is None:
                continue
                
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue
                
            job = self.create_packet_job(raw, parsed, packet_id)
            packet_id += 1
            
            # Update global counters
            with self.stats_lock:
                self.total_packets += 1
                self.total_bytes += len(raw.data)
                if parsed.has_tcp:
                    self.tcp_packets += 1
                elif parsed.has_udp:
                    self.udp_packets += 1
                    
            # First level dispatch: find LB
            lb_idx = hash_tuple(job.tuple) % len(self.lbs)
            self.lbs[lb_idx].input_queue.push(job)
            
        logging.info(f"Done reading {packet_id} packets")
        reader.close()

    def writer_thread_func(self) -> None:
        while self.running or not self.output_queue.empty():
            job = self.output_queue.pop_with_timeout(0.05)
            if job:
                self.output_writer.write_packet(job.ts_sec, job.ts_usec, job.data)

    def handle_output(self, job: PacketJob, action: PacketAction) -> None:
        with self.stats_lock:
            if action == PacketAction.DROP:
                self.dropped_packets += 1
                return
            else:
                self.forwarded_packets += 1
                
        self.output_queue.push(job)

    def create_packet_job(self, raw: RawPacket, parsed: ParsedPacket, packet_id: int) -> PacketJob:
        from ..utils.helpers import str_to_ip
        src_ip = str_to_ip(parsed.src_ip)
        dst_ip = str_to_ip(parsed.dest_ip)
        
        t = FiveTuple(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol
        )
        
        return PacketJob(
            packet_id=packet_id,
            tuple=t,
            data=raw.data,
            payload_offset=parsed.payload_offset,
            payload_length=parsed.payload_length,
            tcp_flags=parsed.tcp_flags,
            ts_sec=raw.ts_sec,
            ts_usec=raw.ts_usec
        )

    def print_report(self) -> None:
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {self.total_packets:<12}                           ║")
        print(f"║ Total Bytes:        {self.total_bytes:<12}                           ║")
        print(f"║ TCP Packets:        {self.tcp_packets:<12}                           ║")
        print(f"║ UDP Packets:        {self.udp_packets:<12}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Forwarded:          {self.forwarded_packets:<12}                           ║")
        print(f"║ Dropped:            {self.dropped_packets:<12}                           ║")
        
        # Thread stats
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ THREAD STATISTICS                                             ║")
        for i, lb in enumerate(self.lbs):
            print(f"║   LB{i} dispatched:   {lb.packets_dispatched:<12}                           ║")
        for i, fp in enumerate(self.fps):
            print(f"║   FP{i} processed:    {fp.packets_processed:<12}                           ║")
            
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                   APPLICATION BREAKDOWN                       ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        
        # Collect and print app breakdown across all threads
        app_counts: Dict[AppType, int] = {}
        detected_snis: Dict[str, AppType] = {}
        
        for fp in self.fps:
            def collect(conn: Connection):
                app_counts[conn.app_type] = app_counts.get(conn.app_type, 0) + conn.packets_in + conn.packets_out
                if conn.sni:
                    detected_snis[conn.sni] = conn.app_type
            fp.conn_tracker.for_each(collect)
            
        sorted_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)
        total_p = self.total_packets
        
        for app, count in sorted_apps:
            pct = (100.0 * count / total_p) if total_p > 0 else 0.0
            bar_len = int(pct / 5)
            bar = '#' * bar_len
            from .types import app_type_to_string
            app_str = app_type_to_string(app)
            print(f"║ {app_str:<15} {count:>8} {pct:>5.1f}% {bar:<20}  ║")
            
        print("╚══════════════════════════════════════════════════════════════╝")
        
        if detected_snis:
            print("\n[Detected Domains/SNIs]")
            for sni, app in sorted(detected_snis.items()):
                from .types import app_type_to_string
                print(f"  - {sni} -> {app_type_to_string(app)}")


# =============================================================================
# Single-threaded DPI Engine (SingleThreadedEngine)
# =============================================================================
class SingleThreadedEngine:
    def __init__(self, rules_file: Optional[str] = None):
        self.rule_manager = RuleManager()
        if rules_file:
            self.rule_manager.load_rules(rules_file)
            
        self.connections: Dict[FiveTuple, Connection] = {}
        
        # Stats
        self.total_packets = 0
        self.forwarded = 0
        self.dropped = 0
        self.app_stats: Dict[AppType, int] = {}
        self.detected_snis: Dict[str, AppType] = {}

    def process(self, input_file: str, output_file: str) -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False
            
        writer = PcapWriter()
        if not writer.open(output_file, reader.get_global_header_dict()):
            reader.close()
            return False
            
        print("\n"
              "╔══════════════════════════════════════════════════════════════╗\n"
              "║                    DPI ENGINE v1.0                            ║\n"
              "╚══════════════════════════════════════════════════════════════╝\n")
              
        logging.info("Processing packets...")
        
        from ..utils.helpers import str_to_ip
        from .types import sni_to_app_type, app_type_to_string
        from ..dpi.extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor
        
        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break
                
            self.total_packets += 1
            
            parsed = PacketParser.parse(raw)
            if parsed is None or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                # Unparsed or non-IP/non-TCP/UDP is forwarded by default in simple mode
                self.forwarded += 1
                writer.write_packet(raw.ts_sec, raw.ts_usec, raw.data)
                continue
                
            src_ip = str_to_ip(parsed.src_ip)
            dst_ip = str_to_ip(parsed.dest_ip)
            
            t = FiveTuple(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol
            )
            
            # Get or create flow (checking bidirectionally)
            flow = None
            if t in self.connections:
                flow = self.connections[t]
            elif t.reverse() in self.connections:
                flow = self.connections[t.reverse()]
            else:
                flow = Connection(tuple=t)
                self.connections[t] = flow
                
            flow.packets_out += 1
            flow.bytes_out += len(raw.data)
            
            # Inspect payload for TLS Client Hello (HTTPS)
            payload = raw.data[parsed.payload_offset:]
            if ((flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTPS) and 
                not flow.sni and parsed.has_tcp and parsed.dest_port == 443 and len(payload) > 5):
                
                sni = SNIExtractor.extract(payload)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)
                    self.detected_snis[sni] = flow.app_type

            # HTTP Host extraction
            if ((flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTP) and
                not flow.sni and parsed.has_tcp and parsed.dest_port == 80 and len(payload) > 0):
                
                host = HTTPHostExtractor.extract(payload)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)
                    self.detected_snis[host] = flow.app_type

            # DNS Query extraction
            if (flow.app_type == AppType.UNKNOWN and 
                (parsed.dest_port == 53 or parsed.src_port == 53) and len(payload) > 0):
                
                domain = DNSExtractor.extract_query(payload)
                if domain:
                    flow.sni = domain
                    flow.app_type = AppType.DNS
                    self.detected_snis[domain] = AppType.DNS
                else:
                    flow.app_type = AppType.DNS

            # Port fallbacks
            if flow.app_type == AppType.UNKNOWN:
                if parsed.dest_port == 443:
                    flow.app_type = AppType.HTTPS
                elif parsed.dest_port == 80:
                    flow.app_type = AppType.HTTP
                    
            # Check rules
            if not flow.state == ConnectionState.BLOCKED:
                reason = self.rule_manager.should_block(
                    src_ip,
                    parsed.dest_port,
                    flow.app_type,
                    flow.sni
                )
                if reason:
                    flow.state = ConnectionState.BLOCKED
                    logging.info(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_type_to_string(flow.app_type)}"
                          f"{': ' + flow.sni if flow.sni else ''})")
                          
            # Update app stats (per-packet counting)
            self.app_stats[flow.app_type] = self.app_stats.get(flow.app_type, 0) + 1
            
            # Forward or drop
            if flow.state == ConnectionState.BLOCKED:
                self.dropped += 1
            else:
                self.forwarded += 1
                writer.write_packet(raw.ts_sec, raw.ts_usec, raw.data)
                
        reader.close()
        writer.close()
        
        # Print report
        self.print_report()
        return True

    def print_report(self) -> None:
        from .types import app_type_to_string
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                       ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {self.total_packets:<10}                             ║")
        print(f"║ Forwarded:          {self.forwarded:<10}                             ║")
        print(f"║ Dropped:            {self.dropped:<10}                             ║")
        print(f"║ Active Flows:       {len(self.connections):<10}                             ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                    APPLICATION BREAKDOWN                     ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        
        sorted_apps = sorted(self.app_stats.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = 100.0 * count / self.total_packets if self.total_packets > 0 else 0
            bar_len = int(pct / 5)
            bar = '#' * bar_len
            print(f"║ {app_type_to_string(app):<15} {count:>8} {pct:>5.1f}% {bar:<20}  ║")
            
        print("╚══════════════════════════════════════════════════════════════╝")
        
        if self.detected_snis:
            print("\n[Detected Applications/Domains]")
            for sni, app in sorted(self.detected_snis.items()):
                print(f"  - {sni} -> {app_type_to_string(app)}")
