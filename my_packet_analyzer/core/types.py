from dataclasses import dataclass, field
from enum import Enum, auto
import time

class AppType(Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    # Specific applications (detected via SNI)
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23  # Keep last for counting

def app_type_to_string(app: AppType) -> str:
    mapping = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare"
    }
    return mapping.get(app, "Unknown")

def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
        
    lower_sni = sni.lower()
    
    # Check for known patterns
    # Google (including YouTube, which is owned by Google)
    if any(x in lower_sni for x in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        # 1. Google
        # 2. YouTube
        # 3. Facebook
        # 4. Instagram
        # 5. WhatsApp
        # 6. Twitter
        # 7. Netflix
        # 8. Amazon
        # 9. Microsoft
        # 10. Apple
        # 11. Telegram
        # 12. TikTok
        # 13. Spotify
        # 14. Zoom
        # 15. Discord
        # 16. GitHub
        # 17. Cloudflare
        # Let's keep this exact order of checks.
        return AppType.GOOGLE
        
    if any(x in lower_sni for x in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return AppType.YOUTUBE
        
    if any(x in lower_sni for x in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return AppType.FACEBOOK
        
    if any(x in lower_sni for x in ["instagram", "cdninstagram"]):
        return AppType.INSTAGRAM
        
    if any(x in lower_sni for x in ["whatsapp", "wa.me"]):
        return AppType.WHATSAPP
        
    if any(x in lower_sni for x in ["twitter", "twimg", "x.com", "t.co"]):
        return AppType.TWITTER
        
    if any(x in lower_sni for x in ["netflix", "nflxvideo", "nflximg"]):
        return AppType.NETFLIX
        
    if any(x in lower_sni for x in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return AppType.AMAZON
        
    if any(x in lower_sni for x in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return AppType.MICROSOFT
        
    if any(x in lower_sni for x in ["apple", "icloud", "mzstatic", "itunes"]):
        return AppType.APPLE
        
    if any(x in lower_sni for x in ["telegram", "t.me"]):
        return AppType.TELEGRAM
        
    if any(x in lower_sni for x in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return AppType.TIKTOK
        
    if any(x in lower_sni for x in ["spotify", "scdn.co"]):
        return AppType.SPOTIFY
        
    if "zoom" in lower_sni:
        return AppType.ZOOM
        
    if any(x in lower_sni for x in ["discord", "discordapp"]):
        return AppType.DISCORD
        
    if any(x in lower_sni for x in ["github", "githubusercontent"]):
        return AppType.GITHUB
        
    if any(x in lower_sni for x in ["cloudflare", "cf-"]):
        return AppType.CLOUDFLARE
        
    # If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType.HTTPS

class ConnectionState(Enum):
    NEW = auto()
    ESTABLISHED = auto()
    CLASSIFIED = auto()
    BLOCKED = auto()
    CLOSED = auto()

class PacketAction(Enum):
    FORWARD = auto()
    DROP = auto()
    INSPECT = auto()
    LOG_ONLY = auto()

@dataclass(frozen=True)
class FiveTuple:
    src_ip: int       # uint32 in host byte order (little-endian bytes representation)
    dst_ip: int       # uint32 in host byte order
    src_port: int     # uint16
    dst_port: int     # uint16
    protocol: int     # uint8 (TCP=6, UDP=17)

    def reverse(self) -> 'FiveTuple':
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )

    def to_string(self) -> str:
        def ip_to_str(ip_val: int) -> str:
            return f"{(ip_val >> 0) & 0xFF}.{(ip_val >> 8) & 0xFF}.{(ip_val >> 16) & 0xFF}.{(ip_val >> 24) & 0xFF}"

        proto_str = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else "?")
        return f"{ip_to_str(self.src_ip)}:{self.src_port} -> {ip_to_str(self.dst_ip)}:{self.dst_port} ({proto_str})"

    def __str__(self) -> str:
        return self.to_string()

@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    action: PacketAction = PacketAction.FORWARD
    
    # For TCP state tracking
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False

@dataclass
class PacketJob:
    packet_id: int
    tuple: FiveTuple
    data: bytes
    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0
    ts_sec: int = 0
    ts_usec: int = 0
