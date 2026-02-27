#!/usr/bin/env python3
import argparse
import json
from erebus.extractor import ErebusExtractor

def main():
    parser = argparse.ArgumentParser(
        description="🕸️  Project Erebus — Dark Web CTI Extractor",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Hedef .onion adresi\nÖrnek: -u http://example.onion"
    )
    parser.add_argument(
        "-o", "--output",
        help="Sonucu JSON dosyasına kaydet\nÖrnek: -o sonuc.json",
        default=None
    )
    parser.add_argument(
        "-p", "--port",
        help="Tor SOCKS5 port (varsayılan: 9050)",
        type=int,
        default=9050
    )

    args = parser.parse_args()

    print(f"\n🕸️  Erebus başlatılıyor...")
    print(f"🎯 Hedef: {args.url}")
    print(f"🔌 Tor port: {args.port}\n")

    extractor = ErebusExtractor(tor_port=args.port)
    result = extractor.harvest(args.url)
    data = result.to_dict()

    # Ekrana yaz
    print(json.dumps(data, indent=2))

    # Özet
    artifacts = data["artifacts"]
    print("\n📊 ÖZET:")
    print(f"  💰 Bitcoin cüzdanı : {len(artifacts['bitcoin_wallets'])}")
    print(f"  🔒 Monero cüzdanı  : {len(artifacts['monero_wallets'])}")
    print(f"  📊 Analytics ID    : {len(artifacts['google_analytics'])}")
    print(f"  🔑 PGP fingerprint : {len(artifacts['pgp_fingerprints'])}")
    print(f"  📧 Email adresi    : {len(artifacts['email_addresses'])}")
    print(f"  🖥️  Server banner   : {artifacts['server_banner']}")
    print(f"  🔐 PGP tespit      : {'✅' if artifacts['pgp_detected'] else '❌'}")

    # Dosyaya kaydet
    if args.output:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n💾 Sonuç kaydedildi: {args.output}")

if __name__ == "__main__":
    main()
