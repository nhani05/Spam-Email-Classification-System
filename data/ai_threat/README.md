# AI Threat Training Data

This directory separates production training data from smoke-test fixtures.

- `raw/`: local copies of external sources such as PhishFuzzer, Nazario, SpamAssassin, Enron, PhishTank, and URLhaus exports.
- `interim/`: temporary imported data before canonical validation.
- `canonical/`: production-ready canonical CSVs used by the retraining command.
- `manifests/`: source manifests, checksums, validation reports, and dataset versions.
- `feedback/`: reviewed feedback exports approved for retraining.
- `fixtures/`: tiny test fixtures.

The files `email_threat_seed.csv` and `url_threat_seed.csv` are legacy smoke fixtures. Production retraining must use canonical data built from external or reviewed sources.
