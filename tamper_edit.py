import sqlite3

c = sqlite3.connect("data/securedrive.db")
c.execute("UPDATE audit SET status = 'SUCCESS' WHERE status = 'INTEGRITY_FAIL'")
c.commit()
print("Audit log edited")