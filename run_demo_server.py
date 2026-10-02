"""Boot aibank with a FAKE Flutterwave transport for end-to-end demoing."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from http.server import ThreadingHTTPServer
from aibank.api import make_handler
from aibank.bank import Bank
from aibank.flutterwave import FlutterwaveClient
from tests.fake_flw import FakeFLW

db = os.environ.get("AIBANK_DB", "demo.db")
if os.path.exists(db):
    os.remove(db)
bank = Bank(db, flw=FlutterwaveClient(secret_key="FLWSECK_TEST-fake", opener=FakeFLW()))
srv = ThreadingHTTPServer(("127.0.0.1", 8077), make_handler(bank))
print("demo server on 8077", flush=True)
srv.serve_forever()
