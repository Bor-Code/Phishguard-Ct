from phishguard.storage import DatabaseManager, FlaggedRecord


def create_sample_record(
    domain: str = "paypa1-security.com",
    brand: str = "paypal",
    score: float = 0.88,
    status: str = "flagged",
) -> FlaggedRecord:
    return FlaggedRecord(
        domain=domain,
        target_brand=brand,
        matched_term="paypa1",
        composite_score=score,
        score_levenshtein=0.83,
        score_keyboard=0.92,
        score_homoglyph=1.0,
        score_affix=0.85,
        is_live=True,
        http_status=200,
        final_url=f"https://{domain}/login",
        cert_issuer="Let's Encrypt",
        cert_age_hours=2.5,
        is_free_ca=True,
        has_password_input=True,
        has_login_form=True,
        page_title="PayPal Security Login",
        confidence_multiplier=1.35,
        final_confidence_score=round(score * 1.35, 4),
        risk_factors=["password_input_detected", "newly_issued_certificate"],
        status=status,
    )


def test_database_initialization_and_migrations(tmp_path):
    db_file = tmp_path / "test_phishguard.db"
    db = DatabaseManager(database_path=db_file)
    db.initialize()

    conn = db.connect()
    cursor = conn.execute("SELECT version FROM schema_migrations")
    versions = [row[0] for row in cursor.fetchall()]
    assert 1 in versions
    db.close()


def test_record_detection_and_retrieval():
    with DatabaseManager(database_path=":memory:") as db:
        record = create_sample_record()
        record_id = db.record_detection(record)
        assert record_id > 0

        retrieved = db.get_domain(record.domain)
        assert retrieved is not None
        assert retrieved.id == record_id
        assert retrieved.domain == "paypa1-security.com"
        assert retrieved.target_brand == "paypal"
        assert retrieved.is_live is True
        assert retrieved.is_free_ca is True
        assert retrieved.has_password_input is True
        assert "password_input_detected" in retrieved.risk_factors
        assert retrieved.status == "flagged"


def test_record_detection_upsert():
    with DatabaseManager(database_path=":memory:") as db:
        initial = create_sample_record(score=0.80)
        id1 = db.record_detection(initial)

        updated = create_sample_record(score=0.95, status="verified")
        id2 = db.record_detection(updated)

        assert id1 == id2
        retrieved = db.get_domain(initial.domain)
        assert retrieved is not None
        assert retrieved.composite_score == 0.95
        assert retrieved.status == "verified"
        assert db.count_flagged() == 1


def test_list_flagged_with_filters():
    with DatabaseManager(database_path=":memory:") as db:
        db.record_detection(
            create_sample_record("paypa1.com", "paypal", 0.90, "flagged")
        )
        db.record_detection(
            create_sample_record("g00gle.com", "google", 0.85, "flagged")
        )
        db.record_detection(
            create_sample_record("micr0soft.com", "microsoft", 0.70, "dismissed")
        )

        all_records = db.list_flagged(min_score=0.0)
        assert len(all_records) == 3

        paypal_records = db.list_flagged(target_brand="paypal")
        assert len(paypal_records) == 1
        assert paypal_records[0].domain == "paypa1.com"

        high_score_records = db.list_flagged(min_score=1.10)
        assert len(high_score_records) >= 2

        dismissed_records = db.list_flagged(status="dismissed")
        assert len(dismissed_records) == 1
        assert dismissed_records[0].domain == "micr0soft.com"


def test_update_status_and_count():
    with DatabaseManager(database_path=":memory:") as db:
        record = create_sample_record()
        db.record_detection(record)

        assert db.count_flagged(status="flagged") == 1
        assert db.count_flagged(status="alert_sent") == 0

        updated = db.update_status("paypa1-security.com", "alert_sent")
        assert updated is True

        retrieved = db.get_domain("paypa1-security.com")
        assert retrieved is not None
        assert retrieved.status == "alert_sent"
        assert db.count_flagged(status="alert_sent") == 1

        not_found = db.update_status("nonexistent.com", "alert_sent")
        assert not_found is False
