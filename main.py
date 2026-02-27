#!/usr/bin/env python3
import argparse
import json
from erebus.extractor import ErebusExtractor
from erebus.correlator import IdentifierCorrelator
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        description="🕸️  Project Erebus — Dark Web CTI Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── HARVEST komutu ──
    harvest_parser = subparsers.add_parser(
        "harvest",
        help="Hedef .onion adresinden artifact topla"
    )
    harvest_parser.add_argument("-u", "--url", required=True, help="Hedef .onion adresi")
    harvest_parser.add_argument("-o", "--output", default=None, help="Sonucu JSON'a kaydet")
    harvest_parser.add_argument("-p", "--port", type=int, default=9050, help="Tor SOCKS5 port")

    # ── CORRELATE komutu ──
    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Birden fazla JSON sonucunu karşılaştır, aynı operatörü bul"
    )
    correlate_parser.add_argument(
        "files",
        nargs="+",
        help="Karşılaştırılacak JSON dosyaları\nÖrnek: sonuc1.json sonuc2.json sonuc3.json"
    )

    args = parser.parse_args()

    # ── HARVEST ──
    if args.command == "harvest":
        print(f"\n🕸️  Erebus — HARVEST modu")
        print(f"🎯 Hedef : {args.url}")
        print(f"🔌 Port  : {args.port}\n")

        extractor = ErebusExtractor(tor_port=args.port)
        result = extractor.harvest(args.url)
        data = result.to_dict()

        print(json.dumps(data, indent=2))

        a = data["artifacts"]
        print("\n📊 ÖZET:")
        print(f"  💰 Bitcoin    : {len(a['bitcoin_wallets'])}")
        print(f"  🔒 Monero     : {len(a['monero_wallets'])}")
        print(f"  📊 Analytics  : {len(a['google_analytics'])}")
        print(f"  🔑 PGP        : {len(a['pgp_fingerprints'])}")
        print(f"  📧 Email      : {len(a['email_addresses'])}")
        print(f"  🖥️  Banner     : {a['server_banner']}")
        print(f"  🔐 PGP blok   : {'✅' if a['pgp_detected'] else '❌'}")

        if args.output:
            with open(args.output, "w") as f:
                json.dump(data, f, indent=2)
            print(f"\n💾 Kaydedildi: {args.output}")

    # ── CORRELATE ──
    elif args.command == "correlate":
        print(f"\n🕸️  Erebus — CORRELATE modu")
        print(f"📂 Dosyalar: {', '.join(args.files)}\n")

        correlator = IdentifierCorrelator()

        for f in args.files:
            if not Path(f).exists():
                print(f"❌ Dosya bulunamadı: {f}")
                continue
            correlator.ingest(f)
            print(f"✅ Yüklendi: {f}")

        print(f"\n📊 İNDEKS ÖZETİ:")
        summary = correlator.summary()
        print(f"  📌 Toplam site        : {summary['total_sites_indexed']}")
        print(f"  🔍 Unique identifier  : {summary['unique_identifiers']}")
        print(f"  🔗 Paylaşılan ID      : {summary['shared_identifiers']}")

        print(f"\n🔗 BAĞLANTI ANALİZİ:")
        found_any = False
        for f in args.files:
            data = json.loads(Path(f).read_text())
            site = data["target"]
            for link in correlator.find_links(site):
                found_any = True
                print(f"\n  🎯 {site}")
                print(f"  ↔️  {link['linked_site']}")
                print(f"  🔗 Paylaşılan: {', '.join(link['shared_identifiers'])}")
                print(f"  ⚠️  Güven: {link['confidence']}")

        if not found_any:
            print("  Ortak identifier bulunamadı.")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()


