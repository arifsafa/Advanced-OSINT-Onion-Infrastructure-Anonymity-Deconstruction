import requests
import re
from dataclasses import dataclass, field
from typing import Optional
import hashlib
import time

@dataclass
class ArtifactBundle:
    target: str
    timestamp: float = field(default_factory=time.time)
    bitcoin_wallets: list[str] = field(default_factory=list)
    monero_wallets: list[str] = field(default_factory=list)
    google_analytics: list[str] = field(default_factory=list)
    pgp_fingerprints: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    server_banner: Optional[str] = None
    pgp_detected: bool = False
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "sha256_fingerprint": hashlib.sha256(self.target.encode()).hexdigest()[:16],
            "artifacts": {
                "bitcoin_wallets": self.bitcoin_wallets,
                "monero_wallets": self.monero_wallets,
                "google_analytics": self.google_analytics,
                "pgp_fingerprints": self.pgp_fingerprints,
                "email_addresses": self.email_addresses,
                "server_banner": self.server_banner,
                "pgp_detected": self.pgp_detected
            }
        }


class ErebusExtractor:
    """
    Safely routes all requests through local Tor SOCKS5 proxy.
    Uses socks5h:// to ensure DNS resolution happens inside Tor.
    """
    
    BITCOIN_P2PKH   = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    BITCOIN_BECH32  = r'\bbc1[a-z0-9]{39,59}\b'
    MONERO          = r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
    ANALYTICS_UA    = r'UA-\d{4,10}-\d{1,4}'
    ANALYTICS_GA4   = r'G-[A-Z0-9]{10}'
    PGP_FINGERPRINT = r'[0-9A-F]{4}[\s][0-9A-F]{4}[\s][0-9A-F]{4}[\s][0-9A-F]{4}[\s][0-9A-F]{4}'
    EMAIL           = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    def __init__(self, tor_port: int = 9050, timeout: int = 25):
        self.proxies = {
            'http':  f'socks5h://127.0.0.1:{tor_port}',
            'https': f'socks5h://127.0.0.1:{tor_port}'
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        self.timeout = timeout

    def harvest(self, onion_url: str) -> ArtifactBundle:
        bundle = ArtifactBundle(target=onion_url)
        try:
            resp = requests.get(
                onion_url,
                proxies=self.proxies,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            html = resp.text
            bundle.server_banner    = resp.headers.get('Server', None)
            bundle.bitcoin_wallets  = list(set(re.findall(self.BITCOIN_P2PKH, html) + re.findall(self.BITCOIN_BECH32, html)))
            bundle.monero_wallets   = list(set(re.findall(self.MONERO, html)))
            bundle.google_analytics = list(set(re.findall(self.ANALYTICS_UA, html) + re.findall(self.ANALYTICS_GA4, html)))
            bundle.pgp_fingerprints = list(set(re.findall(self.PGP_FINGERPRINT, html)))
            bundle.email_addresses  = list(set(re.findall(self.EMAIL, html)))
            bundle.pgp_detected     = "BEGIN PGP PUBLIC KEY" in html
        except requests.exceptions.ConnectTimeout:
            bundle.server_banner = "TIMEOUT"
        except requests.exceptions.RequestException as e:
            bundle.server_banner = f"ERROR: {type(e).__name__}"
        return bundle
