## ADDED Requirements

### Requirement: Indicator extraction for campaign analysis
The system SHALL extract indicators of compromise from analyzed emails, including sender addresses, sender domains, reply-to domains, URLs, final domains, QR payloads, suspicious files, impersonated brands, keywords, timestamps, and threat labels.

#### Scenario: Extract indicators from batch email
- **WHEN** an MBOX email is analyzed during batch processing
- **THEN** the system stores or returns extracted indicators linked to that email analysis result

#### Scenario: Extract indicators from QR result
- **WHEN** a QR image payload is decoded during an email or image analysis workflow
- **THEN** the decoded payload and derived URL or payment indicators are available to campaign analysis

### Requirement: Campaign similarity scoring
The system SHALL compute a campaign similarity score between suspicious emails using text similarity, domain overlap, URL overlap, sender-domain similarity, brand overlap, QR payload overlap, threat-label overlap, and time-window proximity.

#### Scenario: Same phishing domain and similar text
- **WHEN** two suspicious emails share a phishing domain and have similar subject or body content
- **THEN** their campaign similarity score meets or exceeds the configured grouping threshold

#### Scenario: Different benign newsletters
- **WHEN** two low-risk emails share generic words but do not share risky domains, brands, QR payloads, or threat labels
- **THEN** their campaign similarity score remains below the grouping threshold

### Requirement: Campaign clustering and summaries
The system SHALL group related suspicious emails into campaign records with campaign id, primary threat label, risk level, email count, first seen time, last seen time, top domains, top brands, representative reasons, and affected users when available.

#### Scenario: Detect campaign in MBOX upload
- **WHEN** a user uploads an MBOX file containing multiple related phishing emails
- **THEN** the batch result includes at least one campaign summary for the related emails

#### Scenario: Single suspicious email
- **WHEN** only one suspicious email is analyzed and no related emails meet the grouping threshold
- **THEN** the system treats it as an isolated high-risk email rather than forcing a campaign group

### Requirement: Threat graph relationships
The system SHALL expose graph-ready relationships among emails, senders, URLs, domains, QR payloads, brands, threat labels, campaigns, and users for selected campaign investigations.

#### Scenario: Build graph for selected campaign
- **WHEN** a user opens a campaign detail view
- **THEN** the system returns nodes and edges that connect the campaign to its emails, indicators, brands, and domains

#### Scenario: Limit graph size
- **WHEN** a campaign contains more indicators than the configured graph display limit
- **THEN** the system prioritizes high-risk and high-frequency nodes and reports that the graph was truncated

### Requirement: Exportable threat intelligence reports
The system SHALL allow users to export campaign intelligence as a structured report containing summary, timeline, risk assessment, indicators, affected emails, evidence, and recommended actions.

#### Scenario: Export campaign report
- **WHEN** a campaign has been detected from batch or historical analysis
- **THEN** the user can download a report in at least one structured format such as CSV, JSON, or Markdown

#### Scenario: No campaign available
- **WHEN** no campaign exists for the selected analysis scope
- **THEN** the system explains that no campaign report can be generated
