use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use tempfile::TempDir;

const VALID_TOML: &str = r"
chain_id = 4663
max_hops = 4
pool_cap = 2000
stale_timeout_seconds = 60
recovery_gap_blocks = 1000
dirty_lag_milliseconds = 500
request_cu_ceiling = 24000000
websocket_bytes_ceiling = 5000000000
database_limit_bytes = 10000000000
";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_shadow-bot")
}

fn snapshot_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/service/snapshot.json")
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/pools.example.csv")
}

fn write_config(dir: &TempDir, content: &str) -> PathBuf {
    let path = dir.path().join("shadow.toml");
    fs::write(&path, content).unwrap();
    path
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(binary());
    command.args(args).env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    command.env("PATH", "/usr/bin:/bin");
    command.output().unwrap()
}

fn rpc_env() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "ROBINHOOD_HTTP_RPC_URL",
            "https://example.test/v2/secret-http",
        ),
        ("ROBINHOOD_WS_RPC_URL", "wss://example.test/v2/secret-ws"),
    ]
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn utc_today() -> (i32, u32, u32) {
    let millis = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let days = millis.div_euclid(86_400_000);
    civil_from_days(days)
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (
        i32::try_from(year).unwrap(),
        u32::try_from(month).unwrap(),
        u32::try_from(day).unwrap(),
    )
}

#[test]
fn validate_config_rejects_wrong_chain_and_redacts_urls() {
    let directory = tempfile::tempdir().unwrap();
    let env = rpc_env();

    let wrong_chain = VALID_TOML.replace("chain_id = 4663", "chain_id = 1");
    let config = write_config(&directory, &wrong_chain);
    let output = run(
        &["validate-config", "--config", config.to_str().unwrap()],
        &env,
    );
    assert!(!output.status.success());

    let config = write_config(&directory, VALID_TOML);
    let output = run(
        &["validate-config", "--config", config.to_str().unwrap()],
        &env,
    );
    assert!(output.status.success());
    let rendered = stdout(&output);
    assert!(rendered.contains("configuration valid"));
    assert!(!rendered.contains("secret-http"));
    assert!(!rendered.contains("http-secret"));
    assert!(!rendered.to_lowercase().contains("rpc_url"));
}

#[test]
fn verify_catalog_parses_or_rejects_a_manifest_offline() {
    let output = run(
        &[
            "verify-catalog",
            "--manifest",
            manifest_path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(output.status.success());
    assert!(stdout(&output).contains("manifest valid"));

    let directory = tempfile::tempdir().unwrap();
    let bad = directory.path().join("bad.csv");
    fs::write(
        &bad,
        "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,source\n\
         4663,not-an-address,0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6,0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002,997,1000,s\n",
    )
    .unwrap();
    let output = run(
        &["verify-catalog", "--manifest", bad.to_str().unwrap()],
        &[],
    );
    assert!(!output.status.success());
}

#[test]
fn run_writes_observations_and_never_leaks_urls() {
    let directory = tempfile::tempdir().unwrap();
    let config = write_config(&directory, VALID_TOML);
    let db = directory.path().join("shadow.sqlite");
    let output = run(
        &[
            "run",
            "--config",
            config.to_str().unwrap(),
            "--snapshot",
            snapshot_path().to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
        ],
        &rpc_env(),
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let rendered = stdout(&output);
    assert!(rendered.contains("pools=2"));
    assert!(rendered.contains("cycles="));
    assert!(rendered.contains("recorded="));
    assert!(!rendered.contains("secret-http"));
    assert!(!rendered.contains("secret-ws"));
}

#[test]
fn replay_matches_stored_results_and_daily_report_shows_capture_rate_unavailable() {
    let directory = tempfile::tempdir().unwrap();
    let config = write_config(&directory, VALID_TOML);
    let db = directory.path().join("shadow.sqlite");
    let output = run(
        &[
            "run",
            "--config",
            config.to_str().unwrap(),
            "--snapshot",
            snapshot_path().to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
        ],
        &rpc_env(),
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let replayed = run(
        &["replay-observation", "1", "--db", db.to_str().unwrap()],
        &[],
    );
    assert!(replayed.status.success(), "stderr: {}", stderr(&replayed));
    assert!(stdout(&replayed).contains("matched=true"));

    let missing = run(
        &["replay-observation", "9999", "--db", db.to_str().unwrap()],
        &[],
    );
    assert!(!missing.status.success());

    let (year, month, day) = utc_today();
    let report = run(
        &[
            "daily-report",
            "--db",
            db.to_str().unwrap(),
            "--date",
            &format!("{year:04}-{month:02}-{day:02}"),
        ],
        &[],
    );
    assert!(report.status.success(), "stderr: {}", stderr(&report));
    let rendered = stdout(&report);
    assert!(rendered.contains("capture_rate=unavailable"));
    assert!(rendered.contains("valid_observations="));
    assert!(!rendered.to_lowercase().contains("rpc_url"));
}

#[test]
fn help_has_no_signing_or_send_command() {
    let output = run(&["--help"], &[]);
    assert!(output.status.success());
    let help = format!("{}\n{}", stdout(&output), stderr(&output)).to_lowercase();
    for command in [
        "validate-config",
        "verify-catalog",
        "run",
        "replay-observation",
        "daily-report",
        "measure-cross-venues",
        "gap-vs-toll",
        "build-manifest",
        "quote-manifest",
    ] {
        assert!(help.contains(command));
    }
    assert!(!help.contains("sign"));
    assert!(!help.contains("send"));
    assert!(!help.contains("private key"));
}

#[test]
fn gap_vs_toll_rejects_unknown_venue_without_rpc_access() {
    let directory = tempfile::tempdir().unwrap();
    let csv = directory.path().join("pools.csv");
    fs::write(
        &csv,
        "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
         4663,0xfa00000000000000000000000000000000000001,0x0000000000000000000000000000000000000000,0x1000000000000000000000000000000000000000,0x2000000000000000000000000000000000000000,3000,1000000,v3,,\n",
    )
    .unwrap();
    // A venue label outside v3/v4 is rejected after catalog load but before any
    // RPC call, so this must fail fast with a clear message and no traffic.
    let output = run(
        &[
            "gap-vs-toll",
            "--a",
            csv.to_str().unwrap(),
            "--b",
            csv.to_str().unwrap(),
            "--profile-a",
            "v1",
            "--profile-b",
            "v4",
            "--rpc",
            "https://example.test/rpc",
            "--from",
            "1",
            "--to",
            "2",
        ],
        &[],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unsupported venue"));
}

#[test]
fn gap_vs_toll_help_exposes_selection_filters() {
    let output = run(&["gap-vs-toll", "--help"], &[]);
    assert!(output.status.success());
    let help = format!("{}\n{}", stdout(&output), stderr(&output));
    assert!(help.contains("--min-margin"));
    assert!(help.contains("--max-skew"));
    assert!(help.contains("--csv"));
    assert!(help.contains("--top"));
}

#[test]
fn gap_vs_toll_rejects_full_history_without_route_to_block() {
    // A `from` newer than `to` must fail the range check before any transport
    // work; regression guard for the selection-args plumbing.
    let directory = tempfile::tempdir().unwrap();
    let csv = directory.path().join("pools.csv");
    fs::write(
        &csv,
        "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
         4663,0xfa00000000000000000000000000000000000001,0x0000000000000000000000000000000000000000,0x1000000000000000000000000000000000000000,0x2000000000000000000000000000000000000000,3000,1000000,v3,,\n",
    )
    .unwrap();
    let output = run(
        &[
            "gap-vs-toll",
            "--a",
            csv.to_str().unwrap(),
            "--b",
            csv.to_str().unwrap(),
            "--profile-a",
            "v3",
            "--profile-b",
            "v4",
            "--rpc",
            "https://example.test/rpc",
            "--from",
            "2000",
            "--to",
            "1999",
        ],
        &[],
    );
    assert!(!output.status.success());
}

#[test]
fn build_manifest_expands_selection_offline() {
    let directory = tempfile::tempdir().unwrap();
    let v3 = directory.path().join("v3.csv");
    let v4 = directory.path().join("v4.csv");
    let selection = directory.path().join("selection.csv");
    let out = directory.path().join("manifest.csv");
    let a = "0x1000000000000000000000000000000000000000";
    let b = "0x2000000000000000000000000000000000000000";
    let (lo, hi) = {
        let a_addr: alloy_primitives::Address = a.parse().unwrap();
        let b_addr: alloy_primitives::Address = b.parse().unwrap();
        if a_addr <= b_addr { (a, b) } else { (b, a) }
    };
    fs::write(
        &v3,
        format!(
            "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
             4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n"
        ),
    )
    .unwrap();
    let id = "22".repeat(32);
    fs::write(
        &v4,
        format!(
            "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
             4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},2500,1000000,v4,0x{id},\n"
        ),
    )
    .unwrap();
    fs::write(
        &selection,
        format!(
            "token_lo,token_hi,log2_skew,toll,margin\n\
         {lo},{hi},0.100000,0.005000,0.095000\n",
        ),
    )
    .unwrap();
    let output = run(
        &[
            "build-manifest",
            "--a",
            v3.to_str().unwrap(),
            "--b",
            v4.to_str().unwrap(),
            "--selection",
            selection.to_str().unwrap(),
            out.to_str().unwrap(),
        ],
        &[],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let rendered = stdout(&output);
    assert!(rendered.contains("manifest: 2 pool rows from 1 selected pairs"));
    let rows = fs::read_to_string(&out).unwrap();
    let lower = rows.to_lowercase();
    assert!(lower.contains("0xfa00000000000000000000000000000000000001"));
    assert!(lower.contains("0x8366a39cc670b4001a1121b8f6a443a643e40951"));
    assert!(rows.contains(",v3,,"));
    assert!(rows.contains(",v4,0x22"));
}

#[test]
fn quote_manifest_rejects_unknown_venue_without_rpc_access() {
    let directory = tempfile::tempdir().unwrap();
    let csv = directory.path().join("pools.csv");
    fs::write(
        &csv,
        "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
         4663,0xfa00000000000000000000000000000000000001,0x0000000000000000000000000000000000000000,0x1000000000000000000000000000000000000000,0x2000000000000000000000000000000000000000,3000,1000000,v3,,\n",
    )
    .unwrap();
    // Venue validation precedes any RPC call, so this must fail fast offline.
    let output = run(
        &[
            "quote-manifest",
            "--a",
            csv.to_str().unwrap(),
            "--b",
            csv.to_str().unwrap(),
            "--profile-a",
            "v1",
            "--profile-b",
            "v4",
            "--rpc",
            "https://example.test/rpc",
            "--from",
            "1",
            "--to",
            "2",
        ],
        &[],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unsupported venue"));
}
