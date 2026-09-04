import sqlite3
con = sqlite3.connect('securesite_audit.db')
cur = con.cursor()
cur.execute("UPDATE domains SET is_verified=1 WHERE domain_name='example.com'")
con.commit()
print(cur.rowcount)
con.close()
