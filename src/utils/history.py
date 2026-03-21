from src.utils.db import get_connection
from datetime import datetime

def save_single_prediction(user_id, email, prediction, confidence):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
    INSERT INTO Single_Prediction_History 
    (user_id, email_content, prediction, confidence, created_at)
    VALUES (%s, %s, %s, %s, %s)
    """

    values = (user_id, email, prediction, confidence, datetime.now())

    cursor.execute(query, values)
    conn.commit()

    cursor.close()
    conn.close()