import sqlite3

# Connect to database
def sql_connection():
    try:
        con = sqlite3.connect("file_access.db")
        return con
    except sqlite3.Error:
        print(Error)

# Initialize database if needed
def sql_table(con):
    cursorObj = con.cursor()
    cursorObj.execute("CREATE TABLE IF NOT EXISTS file_access(config_file text, report_file text, pwd_hash blob, iv blob, pad integer, UNIQUE(config_file, report_file))")
    con.commit()

# Add report to database
def sql_insert(con, entities):
    cursorObj = con.cursor()
    try:
        cursorObj.execute("INSERT INTO file_access(config_file, report_file, pwd_hash, iv, pad) VALUES(?, ?, ?, ?, ?)", entities)
    except sqlite3.Error:
        cursorObj.execute("UPDATE file_access SET pwd_hash = ?, iv = ?, pad = ? WHERE (config_file = ? AND report_file = ?)", entities[-3:]+entities[:2])
    con.commit()

# Print database contents (used for debugging)
def print_table(con):
    cursorObj = con.cursor()
    with con:
        cursorObj.execute("SELECT * FROM file_access")
        print(cursorObj.fetchall())

# Fetch report details from database
def sql_fetch(con, filename):
    cursorObj = con.cursor()
    cursorObj.execute("SELECT * FROM file_access WHERE report_file = ?", (filename,))
    row = cursorObj.fetchone()
    return row

