-- ============================================================
-- TẠO CƠ SỞ DỮ LIỆU
-- ============================================================
CREATE DATABASE IF NOT EXISTS spam_detection
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP TABLE IF EXISTS Batch_Prediction_History;
DROP TABLE IF EXISTS Review_Queue;
DROP TABLE IF EXISTS Prediction_Feedback;
DROP TABLE IF EXISTS Campaign_Email;
DROP TABLE IF EXISTS Threat_Campaign;
DROP TABLE IF EXISTS Extracted_Indicator;
DROP TABLE IF EXISTS Prediction_Threat_Metadata;
DROP TABLE IF EXISTS Model_Run;
DROP TABLE IF EXISTS Single_Prediction_History;
DROP TABLE IF EXISTS User;


USE spam_detection;

-- ============================================================
-- BẢNG 1: User
-- ============================================================
CREATE TABLE User (
    id      INT           NOT NULL AUTO_INCREMENT,
    username VARCHAR(12)   NOT NULL UNIQUE,
    password VARCHAR(255)  NOT NULL,
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
-- ADAPTIVE THREAT INTELLIGENCE EXTENSIONS
-- ============================================================
CREATE TABLE Model_Run (
    id INT NOT NULL AUTO_INCREMENT,
    run_id VARCHAR(64) NOT NULL UNIQUE,
    model_name VARCHAR(120) NOT NULL,
    dataset_identity TEXT NULL,
    feature_config JSON NULL,
    taxonomy JSON NULL,
    metrics JSON NULL,
    artifact_paths JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE TABLE Prediction_Threat_Metadata (
    id INT NOT NULL AUTO_INCREMENT,
    prediction_id INT NOT NULL,
    threat_label VARCHAR(80) NOT NULL DEFAULT 'Safe',
    risk_score INT NOT NULL DEFAULT 0,
    risk_level VARCHAR(32) NOT NULL DEFAULT 'Low',
    verdict VARCHAR(120) NOT NULL DEFAULT 'LOW_RISK_EMAIL',
    component_scores JSON NULL,
    indicators JSON NULL,
    reasons JSON NULL,
    recommended_actions JSON NULL,
    campaign_id VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_threat_single_prediction
        FOREIGN KEY (prediction_id) REFERENCES Single_Prediction_History(ID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE Extracted_Indicator (
    id INT NOT NULL AUTO_INCREMENT,
    prediction_id INT NULL,
    indicator_type VARCHAR(40) NOT NULL,
    indicator_value TEXT NOT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    source VARCHAR(40) NOT NULL DEFAULT 'email',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_indicator_type (indicator_type),
    CONSTRAINT fk_indicator_single_prediction
        FOREIGN KEY (prediction_id) REFERENCES Single_Prediction_History(ID)
        ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE Threat_Campaign (
    id INT NOT NULL AUTO_INCREMENT,
    campaign_id VARCHAR(64) NOT NULL UNIQUE,
    primary_threat_label VARCHAR(80) NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    email_count INT NOT NULL DEFAULT 0,
    first_seen VARCHAR(80) NULL,
    last_seen VARCHAR(80) NULL,
    top_domains JSON NULL,
    top_brands JSON NULL,
    representative_reasons JSON NULL,
    report_markdown MEDIUMTEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE TABLE Campaign_Email (
    id INT NOT NULL AUTO_INCREMENT,
    campaign_id VARCHAR(64) NOT NULL,
    prediction_id INT NULL,
    batch_row_index INT NULL,
    similarity_score DECIMAL(6, 4) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_campaign_email_campaign (campaign_id),
    CONSTRAINT fk_campaign_email_single_prediction
        FOREIGN KEY (prediction_id) REFERENCES Single_Prediction_History(ID)
        ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE Prediction_Feedback (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    prediction_id INT NULL,
    feedback ENUM('correct', 'incorrect') NOT NULL,
    corrected_label VARCHAR(80) NULL,
    note TEXT NULL,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    reviewer VARCHAR(80) NULL,
    reviewed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_feedback_user
        FOREIGN KEY (user_id) REFERENCES User(ID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_feedback_prediction
        FOREIGN KEY (prediction_id) REFERENCES Single_Prediction_History(ID)
        ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE Review_Queue (
    id INT NOT NULL AUTO_INCREMENT,
    prediction_id INT NULL,
    feedback_id INT NULL,
    reason VARCHAR(120) NOT NULL,
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    model_label VARCHAR(80) NULL,
    risk_score INT NOT NULL DEFAULT 0,
    evidence JSON NULL,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    approved_label VARCHAR(80) NULL,
    reviewer VARCHAR(80) NULL,
    reviewed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_review_prediction
        FOREIGN KEY (prediction_id) REFERENCES Single_Prediction_History(ID)
        ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT fk_review_feedback
        FOREIGN KEY (feedback_id) REFERENCES Prediction_Feedback(ID)
        ON DELETE SET NULL ON UPDATE CASCADE
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

INSERT INTO Threat_Campaign
    (campaign_id, primary_threat_label, risk_level, risk_score, email_count, first_seen, last_seen, top_domains, top_brands, representative_reasons, report_markdown)
VALUES
('CAMP-DEMO-001', 'Phishing', 'High', 78, 3, '2024-01-26 10:30:00', '2024-01-26 11:00:00',
 JSON_ARRAY('fake-bank.com'), JSON_ARRAY('bank'),
 JSON_ARRAY('Shared phishing domain', 'Urgent credential verification wording'),
 '# Threat Intelligence Report: CAMP-DEMO-001');
