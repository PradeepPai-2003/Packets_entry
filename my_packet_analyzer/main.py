import argparse
import sys
import datetime
import logging
from typing import List, Optional

from .capture.pcap import PcapReader
from .parser.protocols import PacketParser, ParsedPacket, EtherType
from .core.engine import DPIEngine, SingleThreadedEngine
from .core.types import AppType
from .utils.helpers import setup_logging

def print_packet_summary(pkt: ParsedPacket, packet_num: int) -> None:
    """Print packet details matching src/main.cpp format."""
    try:
        dt = datetime.datetime.fromtimestamp(pkt.timestamp_sec)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        time_str = "1970-01-01 00:00:00"

    print(f"\n========== Packet #{packet_num} ==========")
    print(f"Time: {time_str}.{pkt.timestamp_usec:06d}")
    
    # Ethernet layer
    print("\n[Ethernet]")
    print(f"  Source MAC:      {pkt.src_mac}")
    print(f"  Destination MAC: {pkt.dest_mac}")
    ether_type_str = f"0x{pkt.ether_type:04x}"
    if pkt.ether_type == EtherType.IPv4:
        ether_type_str += " (IPv4)"
    elif pkt.ether_type == EtherType.IPv6:
        ether_type_str += " (IPv6)"
    elif pkt.ether_type == EtherType.ARP:
        ether_type_str += " (ARP)"
    print(f"  EtherType:       {ether_type_str}")
    
    # IP layer
    if pkt.has_ip:
        print(f"\n[IPv{pkt.ip_version}]")
        print(f"  Source IP:      {pkt.src_ip}")
        print(f"  Destination IP: {pkt.dest_ip}")
        print(f"  Protocol:       {PacketParser.protocol_to_string(pkt.protocol)}")
        print(f"  TTL:            {pkt.ttl}")
        
    # TCP layer
    if pkt.has_tcp:
        print("\n[TCP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        print(f"  Sequence Number:  {pkt.seq_number}")
        print(f"  Ack Number:       {pkt.ack_number}")
        print(f"  Flags:            {PacketParser.tcp_flags_to_string(pkt.tcp_flags)}")
        
    # UDP layer
    if pkt.has_udp:
        print("\n[UDP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        
    # Payload
    if pkt.payload_length > 0 and pkt.payload_data:
        print("\n[Payload]")
        print(f"  Length: {pkt.payload_length} bytes")
        preview_len = min(pkt.payload_length, 32)
        preview_bytes = pkt.payload_data[:preview_len]
        hex_str = " ".join(f"{b:02x}" for b in preview_bytes)
        print(f"  Preview: {hex_str}", end="")
        if pkt.payload_length > 32:
            print(" ...")
        else:
            print("")


def run_print_mode(input_file: str, max_packets: int) -> int:
    """Run in print mode (replicates main.cpp)."""
    print("====================================")
    print("     Packet Analyzer v1.0")
    print("====================================\n")
    
    reader = PcapReader()
    if not reader.open(input_file):
        return 1
        
    print("\n--- Reading packets ---\n")
    packet_count = 0
    parse_errors = 0
    
    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break
            
        packet_count += 1
        parsed = PacketParser.parse(raw)
        if parsed:
            print_packet_summary(parsed, packet_count)
        else:
            print(f"Warning: Failed to parse packet #{packet_count}", file=sys.stderr)
            parse_errors += 1
            
        if 0 < max_packets <= packet_count:
            print(f"\n(Stopped after {max_packets} packets)")
            break
            
    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")
    
    reader.close()
    return 0


def main(args_list: Optional[List[str]] = None) -> int:
    # Reconfigure standard output streams for UTF-8 compatibility (especially on Windows)
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="DPI Packet Analyzer - Rebuilt in Python",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("input_file", help="Input PCAP file to analyze")
    parser.add_argument("output_file", nargs="?", default=None, help="Output PCAP file for filtered traffic (required for mt/simple modes)")
    
    parser.add_argument(
        "--mode",
        choices=["mt", "simple", "print"],
        default=None,
        help="Execution mode:\n"
             "  mt     - Multi-threaded DPI engine (default if output_file is set)\n"
             "  simple - Single-threaded DPI engine\n"
             "  print  - Simple packet printer (default if output_file is omitted)"
    )
    
    # Blocking rules
    parser.add_argument("--block-ip", action="append", default=[], help="Block source IP address")
    parser.add_argument("--block-app", action="append", default=[], help="Block application type (e.g. YouTube, Google)")
    parser.add_argument("--block-domain", action="append", default=[], help="Block domain suffix or wildcard (e.g. *.tiktok.com)")
    parser.add_argument("--rules", help="Path to rules configuration file")
    
    # Performance configurations (for MT mode)
    parser.add_argument("--lbs", type=int, default=2, help="Number of Load Balancer threads (default: 2)")
    parser.add_argument("--fps", type=int, default=2, help="Number of Fast Path threads per LB (default: 2)")
    
    # Print mode configurations
    parser.add_argument("--max-packets", type=int, default=-1, help="Max packets to print in print mode")
    
    # Utility configurations
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args(args_list)
    
    setup_logging(args.verbose)
    
    # Determine default mode based on output file presence
    mode = args.mode
    if mode is None:
        mode = "mt" if args.output_file else "print"
        
    if mode == "print":
        return run_print_mode(args.input_file, args.max_packets)
        
    # Check output file requirement for filtering modes
    if not args.output_file:
        print("Error: output_file is required for mt and simple modes.", file=sys.stderr)
        parser.print_usage(sys.stderr)
        return 1
        
    if mode == "simple":
        # Single threaded engine
        engine = SingleThreadedEngine(args.rules)
        
        # Apply command line blocking rules
        for ip in args.block_ip:
            engine.rule_manager.block_ip(ip)
        for app_name in args.block_app:
            found = False
            for i in range(int(AppType.APP_COUNT.value)):
                app = AppType(i)
                from .core.types import app_type_to_string
                if app_type_to_string(app) == app_name:
                    engine.rule_manager.block_app(app)
                    found = True
                    break
            if not found:
                print(f"Unknown app type: {app_name}", file=sys.stderr)
        for domain in args.block_domain:
            engine.rule_manager.block_domain(domain)
            
        success = engine.process(args.input_file, args.output_file)
        return 0 if success else 1
        
    else:  # mode == "mt"
        # Multi threaded engine
        config = DPIEngine.Config(
            num_load_balancers=args.lbs,
            fps_per_lb=args.fps,
            rules_file=args.rules,
            verbose=args.verbose
        )
        
        engine = DPIEngine(config)
        if not engine.initialize():
            print("Error: Could not initialize DPI engine.", file=sys.stderr)
            return 1
            
        # Apply command line blocking rules
        for ip in args.block_ip:
            engine.rule_manager.block_ip(ip)
        for app_name in args.block_app:
            found = False
            for i in range(int(AppType.APP_COUNT.value)):
                app = AppType(i)
                from .core.types import app_type_to_string
                if app_type_to_string(app) == app_name:
                    engine.rule_manager.block_app(app)
                    found = True
                    break
            if not found:
                print(f"Unknown app type: {app_name}", file=sys.stderr)
        for domain in args.block_domain:
            engine.rule_manager.block_domain(domain)
            
        success = engine.process_file(args.input_file, args.output_file)
        return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
