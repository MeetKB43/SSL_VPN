import os
os.system("pip install mysql-connector-python")
import mysql.connector

lst_pass = {
    "10.0.2.4":"hello_client_1",
    "10.0.2.3":"client_2_welcome"
    }
passwords = list(lst_pass.items())

#database connectivity
mydb = mysql.connector.connect(
   host="192.168.60.10",
   user="vpn_server",
   password="vpn_pass",
   database="mysql",
   port="3306"
)

mycursor = mydb.cursor()

mycursor.execute("CREATE TABLE Users (IP VARCHAR(255), password VARCHAR(255))")
sql = "INSERT INTO Users (IP, password) VALUES (%s, %s);"

mycursor.executemany(sql, passwords)
mydb.commit()