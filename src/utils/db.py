import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Phuoc.@123",   # đổi theo máy bạn
        database="spam_detection"
    )