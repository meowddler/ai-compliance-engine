from backend.database import engine
from sqlalchemy import text
c = engine.connect()
print("actual scan rows:", c.execute(text("SELECT count(*) FROM scans")).scalar())
print("max id:", c.execute(text("SELECT max(id) FROM scans")).scalar())
print("sequence at:", c.execute(text("SELECT last_value FROM scans_id_seq")).scalar())
c.close()
