use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

const KEY: &str = "integration-test-secret";

#[test]
fn seal_then_verify_fixture_chain() {
    let temp = tempdir().unwrap();
    let bundle = temp.path().join("sealed.json");

    Command::cargo_bin("tierlock")
        .unwrap()
        .env("TIERLOCK_KEY", KEY)
        .args([
            "seal",
            "--contract",
            "fixtures/itinerary.json",
            "--output",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = Command::cargo_bin("tierlock")
        .unwrap()
        .env("TIERLOCK_KEY", KEY)
        .args([
            "verify",
            "--bundle",
            bundle.to_str().unwrap(),
            "--receipts",
            "fixtures/handoffs.jsonl",
            "--now-ms",
            "1893456000000",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["decision"], "allow");
    assert_eq!(report["receipts_checked"], 2);
}

#[test]
fn denied_verification_exits_two_and_writes_report() {
    let temp = tempdir().unwrap();
    let bundle = temp.path().join("sealed.json");
    let receipts = temp.path().join("bad.jsonl");
    fs::write(
        &receipts,
        fs::read_to_string("fixtures/handoffs.jsonl")
            .unwrap()
            .replace("\"tenant_id\":\"acme\"", "\"tenant_id\":\"intruder\""),
    )
    .unwrap();

    Command::cargo_bin("tierlock")
        .unwrap()
        .env("TIERLOCK_KEY", KEY)
        .args([
            "seal",
            "--contract",
            "fixtures/itinerary.json",
            "--output",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tierlock")
        .unwrap()
        .env("TIERLOCK_KEY", KEY)
        .args([
            "verify",
            "--bundle",
            bundle.to_str().unwrap(),
            "--receipts",
            receipts.to_str().unwrap(),
            "--now-ms",
            "1893456000000",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("tenant_mismatch"));
}

#[test]
fn missing_key_is_an_operational_error() {
    Command::cargo_bin("tierlock")
        .unwrap()
        .env_remove("TIERLOCK_KEY")
        .args([
            "seal",
            "--contract",
            "fixtures/itinerary.json",
            "--output",
            "/dev/null",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("TIERLOCK_KEY is not set"));
}
