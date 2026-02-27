from erebus.extractor import ErebusExtractor
import json

extractor = ErebusExtractor()

# Tor bağlantı testi
result = extractor.harvest("https://check.torproject.org")
print(json.dumps(result.to_dict(), indent=2))
print("\n✅ Server banner:", result.server_banner)
print("✅ Tor üzerinden bağlandı!" if result.server_banner else "❌ Bağlantı yok")
