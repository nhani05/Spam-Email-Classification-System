-- ============================================================
-- TẠO CƠ SỞ DỮ LIỆU
-- ============================================================
CREATE DATABASE IF NOT EXISTS spam_detection
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP TABLE IF EXISTS Batch_Prediction_History;
DROP TABLE IF EXISTS Single_Prediction_History;
DROP TABLE IF EXISTS User;


USE spam_detection;

-- ============================================================
-- BẢNG 1: User
-- ============================================================
CREATE TABLE User (
    id      INT           NOT NULL AUTO_INCREMENT,
    username VARCHAR(12)   NOT NULL UNIQUE,
    password VARCHAR(12)   NOT NULL,
    created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ID)
);

-- ============================================================
-- BẢNG 2: Batch Prediction History
-- ============================================================
CREATE TABLE Batch_Prediction_History (
    id           INT          NOT NULL AUTO_INCREMENT,
    user_id      INT          NOT NULL,
    file_name    VARCHAR(50)  NOT NULL,
    total_emails INT          NOT NULL DEFAULT 0,
    spam_count   INT          NOT NULL DEFAULT 0,
    ham_count    INT          NOT NULL DEFAULT 0,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    CONSTRAINT fk_batch_user
        FOREIGN KEY (user_id) REFERENCES User(ID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ============================================================
-- BẢNG 3: Single Prediction History
-- ============================================================
CREATE TABLE Single_Prediction_History (
    ID            INT            NOT NULL AUTO_INCREMENT,
    user_id       INT            NOT NULL,
    email_content TEXT           NOT NULL,
    prediction    enum('SPAM', 'HAM')           NOT NULL,
    confidence    DECIMAL(10, 2) NOT NULL,
    created_at    DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    CONSTRAINT fk_single_user
        FOREIGN KEY (user_id) REFERENCES User(ID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ============================================================
-- DỮ LIỆU MẪU: User
-- ============================================================
INSERT INTO User (username, password, created_at) VALUES
('alice',   'pass123',   '2024-01-10 08:00:00'),
('bob',     'qwerty12',  '2024-01-15 09:30:00'),
('charlie', 'charlie99', '2024-02-01 14:00:00');

-- ============================================================
-- DỮ LIỆU MẪU: Batch Prediction History
-- ============================================================
INSERT INTO Batch_Prediction_History
    (user_id, file_name, total_emails, spam_count, ham_count, created_at)
VALUES
(1, 'inbox_jan.csv',    200, 45,  155, '2024-01-20 10:00:00'),
(1, 'inbox_feb.csv',    150, 30,  120, '2024-02-05 11:00:00'),
(2, 'emails_work.csv',  300, 80,  220, '2024-01-25 09:00:00'),
(3, 'batch_march.csv',  500, 120, 380, '2024-03-01 08:30:00');

-- ============================================================
-- DỮ LIỆU MẪU: Single Prediction History
-- ============================================================
INSERT INTO Single_Prediction_History
    (user_id, email_content, prediction, confidence, created_at)
VALUES
(1,
 'Congratulations! You have won a $1000 gift card. Click here to claim.',
 'spam', 97.50,
 '2024-01-21 08:15:00'),
(1,
 'Hi Alice, please review the attached report before the meeting tomorrow.',
 'ham', 99.10,
 '2024-01-21 09:00:00'),
(2,
 'URGENT: Your bank account has been suspended. Verify now at fake-bank.com',
 'spam', 98.75,
 '2024-01-26 10:30:00'),
(2,
 'Team standup is moved to 10am. Please update your calendar accordingly.',
 'ham', 96.30,
 '2024-01-27 08:00:00'),
(3,
 'Buy cheap meds online! No prescription needed. Limited time offer!!!',
 'spam', 99.00,
 '2024-03-02 07:45:00');