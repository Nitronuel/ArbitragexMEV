use alloy_primitives::U256;
use provider::UsageSnapshot;
use storage::Storage;
use thiserror::Error;

/// One UTC calendar day's shadow-mode summary, rendered for operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyReport {
    /// UTC calendar day `(year, month, day)`.
    pub date: (i32, u32, u32),
    /// Number of valid recorded observations that day.
    pub valid_observations: usize,
    /// Observations with strictly positive estimated gross profit.
    pub positive_observations: usize,
    /// Sum of recorded estimated gross profit (token units).
    pub total_estimated_profit: U256,
    /// Number of ready health intervals covering the day.
    pub ready_intervals: usize,
    /// Number of stale/degraded health intervals covering the day.
    pub stale_intervals: usize,
    /// Aggregated provider usage meters.
    pub usage: UsageSnapshot,
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("failed to read shadow storage: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("no observations or health intervals to report for {year}-{month}-{day}")]
    NoData { year: i32, month: u32, day: u32 },
}

impl DailyReport {
    /// Capture rate is deliberately unavailable in shadow mode because no
    /// transaction is ever sent, so "won" opportunities cannot exist.
    #[must_use]
    pub fn capture_rate(&self) -> Option<f64> {
        None
    }

    /// Renders a concise, URL-free report body.
    #[must_use]
    pub fn render(&self) -> String {
        let (year, month, day) = self.date;
        format!(
            "shadow daily report {year:04}-{month:02}-{day:02}\n\
             valid_observations={}\n\
             positive_observations={}\n\
             total_estimated_profit_token_units={}\n\
             ready_intervals={}\n\
             stale_intervals={}\n\
             request_cu={}\n\
             http_response_bytes={}\n\
             websocket_delivered_bytes={}\n\
             websocket_accounted_bytes={}\n\
             capture_rate=unavailable",
            self.valid_observations,
            self.positive_observations,
            self.total_estimated_profit,
            self.ready_intervals,
            self.stale_intervals,
            self.usage.request_cu,
            self.usage.http_response_bytes,
            self.usage.websocket_delivered_bytes,
            self.usage.websocket_accounted_bytes,
        )
    }
}

/// Aggregates one UTC day of evaluations and health from persistence.
///
/// # Errors
///
/// Returns [`ReportError::NoData`] when the database has no observation or
/// health data on the requested day, or a storage read failure.
pub fn daily_report(
    storage: &Storage,
    year: i32,
    month: u32,
    day: u32,
) -> Result<DailyReport, ReportError> {
    let day_epoch = days_from_civil(year, month, day);

    let observations = storage.load_observations()?;
    let (observed_count, positive, total) = observations
        .into_iter()
        .filter(|(_, record)| epoch_day(record.observed_at_unix_milliseconds) == day_epoch)
        .fold(
            (0_usize, 0_usize, U256::ZERO),
            |(count, positive, total), (_, record)| {
                (
                    count + 1,
                    if record.estimated_profit.is_zero() {
                        positive
                    } else {
                        positive + 1
                    },
                    total + record.estimated_profit,
                )
            },
        );

    let intervals = storage.load_health_intervals()?;
    let mut ready = 0_usize;
    let mut stale = 0_usize;
    for interval in intervals {
        if epoch_day(interval.ended_at_unix_milliseconds) != day_epoch {
            continue;
        }
        if interval.state == "READY" {
            ready += 1;
        } else {
            stale += 1;
        }
    }

    if observed_count == 0 && ready == 0 && stale == 0 {
        return Err(ReportError::NoData { year, month, day });
    }

    Ok(DailyReport {
        date: (year, month, day),
        valid_observations: observed_count,
        positive_observations: positive,
        total_estimated_profit: total,
        ready_intervals: ready,
        stale_intervals: stale,
        usage: storage.usage_summary()?,
    })
}

fn epoch_day(unix_milliseconds: u64) -> i64 {
    i64::try_from(unix_milliseconds).map_or(0, |millis| millis.div_euclid(86_400_000))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = i64::from(year) - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy =
        (153 * (i64::from(month) + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use tempfile::tempdir;

    use super::{ReportError, daily_report, days_from_civil};
    use domain::{CycleId, Fee, PoolId, StateVersion};
    use storage::{HealthInterval, ObservationRecord, RouteStateRecord, Storage};

    fn store_observation(storage: &mut Storage, ms: u64, profit: u128) -> i64 {
        storage
            .record_observation(&ObservationRecord {
                cycle_id: CycleId(1),
                observed_at_unix_milliseconds: ms,
                input: U256::from(100),
                output: U256::from(100 + profit),
                estimated_profit: U256::from(profit),
                route_states: vec![RouteStateRecord {
                    pool_id: PoolId(0),
                    state_version: StateVersion(0),
                    reserve0: U256::from(1_000),
                    reserve1: U256::from(2_000),
                    fee: Fee {
                        numerator: 997,
                        denominator: 1_000,
                    },
                    zero_for_one: true,
                }],
            })
            .unwrap()
    }

    #[test]
    fn utc_day_conversion_is_stable() {
        // 2000-01-01T00:00:00Z is 10,957 days after the 1970-01-01 epoch.
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        // 1970-01-01 is day 0.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        // 2020-02-29 (leap) is epoch day 18_321.
        assert_eq!(days_from_civil(2020, 2, 29), 18_321);
    }

    #[test]
    fn daily_report_aggregates_a_single_utc_day() {
        let directory = tempdir().unwrap();
        let mut storage = Storage::open(&directory.path().join("shadow.sqlite")).unwrap();
        // 2026-08-04 is epoch day 20_669; 2026-08-05 is day 20_670.
        let day_four = 20_669_u64 * 86_400_000;
        let day_five = 20_670_u64 * 86_400_000;
        store_observation(&mut storage, day_four, 30);
        store_observation(&mut storage, day_four + 1, 50);
        // A different day - 2026-08-05 - must be excluded.
        store_observation(&mut storage, day_five, 999);
        storage
            .record_health_interval(&HealthInterval {
                started_at_unix_milliseconds: day_four,
                ended_at_unix_milliseconds: day_four + 60_000,
                state: "READY".to_owned(),
                reason: "bootstrap".to_owned(),
            })
            .unwrap();

        let report = daily_report(&storage, 2026, 8, 4).unwrap();
        assert_eq!(report.date, (2026, 8, 4));
        assert_eq!(report.valid_observations, 2);
        assert_eq!(report.positive_observations, 2);
        assert_eq!(report.total_estimated_profit, U256::from(80));
        assert_eq!(report.ready_intervals, 1);
        assert_eq!(report.stale_intervals, 0);
        assert_eq!(report.capture_rate(), None);
        let text = report.render();
        assert!(text.contains("capture_rate=unavailable"));
        assert!(text.contains("valid_observations=2"));
        assert!(!text.to_lowercase().contains("rpc_url"));
    }

    #[test]
    fn daily_report_errors_without_day_data() {
        let directory = tempdir().unwrap();
        let mut storage = Storage::open(&directory.path().join("shadow.sqlite")).unwrap();
        let day_four = 20_669_u64 * 86_400_000;
        let day_five = 20_670_u64 * 86_400_000;
        store_observation(&mut storage, day_five, 5);
        assert!(matches!(
            daily_report(&storage, 2026, 8, 4),
            Err(ReportError::NoData { .. })
        ));
        let _ = day_four;
    }
}
