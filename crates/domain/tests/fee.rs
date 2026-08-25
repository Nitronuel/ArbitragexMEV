use domain::Fee;

#[test]
fn both_csv_dialects_construct_plausible_fees() {
    // Audit C1: V2 catalogs store keep rates (997/1000), build-manifest
    // output stores fee rates (3000/1_000_000). Both must construct — and
    // represent the same effective economics for an equivalent pool.
    let keep = Fee::keep_rate(997, 1_000).expect("v2 keep rate is plausible");
    assert_eq!(keep.numerator, 997);
    assert_eq!(keep.denominator, 1_000);

    let taken = Fee::fee_rate(3_000, 1_000_000).expect("30 bps fee rate is plausible");
    assert_eq!(taken.numerator, 3_000);
    assert_eq!(taken.denominator, 1_000_000);
}

#[test]
fn implausible_fractions_are_rejected_in_both_readings() {
    // A fee that takes everything: `1/1` under the fee-rate reading keeps
    // nothing; the keep-rate reading of the same row is a legitimate
    // zero-fee pool and stays valid.
    assert!(Fee::fee_rate(1, 1).is_err());
    assert!(Fee::keep_rate(1, 1).is_ok());
    // Keeps less than one part-per-million of the whole.
    assert!(Fee::fee_rate(999_999_999, 1_000_000_000).is_err());
    assert!(Fee::keep_rate(1, 1_000_000_000).is_err());
    // Zero denominator and inverted fractions.
    assert!(Fee::keep_rate(0, 0).is_err());
    assert!(Fee::fee_rate(2_000, 1_000).is_err());
}

#[test]
fn ambiguous_but_plausible_rows_are_accepted() {
    // `500/1000` reads plausibly as keep-50% or fee-50%; the parser accepts
    // whichever reading validates rather than guessing wrong.
    assert!(Fee::keep_rate(500, 1_000).is_ok() || Fee::fee_rate(500, 1_000).is_ok());
}
