use std::{cell::RefCell, collections::VecDeque, rc::Rc, str::FromStr, time::Duration};

use alloy_primitives::Address;
use provider::{
    BudgetExceeded, ChainReader, DisconnectKind, HttpBackend, HttpResponse, LogFilter, LogStream,
    ProviderBudget, RedactedUrl, RetryPolicy, RpcRequest, Sleeper, StreamItem, SubscriptionFilter,
    TransportError, sync_topic,
};
use serde_json::json;

struct MockHttp {
    responses: RefCell<VecDeque<Result<HttpResponse, TransportError>>>,
    requests: Rc<RefCell<Vec<RpcRequest>>>,
}

impl HttpBackend for MockHttp {
    fn request(&self, request: &RpcRequest) -> Result<HttpResponse, TransportError> {
        self.requests.borrow_mut().push(request.clone());
        self.responses.borrow_mut().pop_front().unwrap()
    }
}

#[derive(Clone, Default)]
struct RecordingSleeper(Rc<RefCell<Vec<Duration>>>);

impl Sleeper for RecordingSleeper {
    fn sleep(&self, duration: Duration) {
        self.0.borrow_mut().push(duration);
    }
}

fn policy() -> RetryPolicy {
    RetryPolicy {
        max_retries: 3,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(250),
    }
}

#[test]
fn validates_robinhood_chain_and_rejects_other_chains() {
    for (chain, expected_ok) in [("0x1237", true), ("0x1", false)] {
        let backend = MockHttp {
            responses: RefCell::new(VecDeque::from([Ok(HttpResponse {
                result: json!(chain),
                response_bytes: 10,
            })])),
            requests: Rc::default(),
        };
        let reader = ChainReader::new(
            backend,
            RecordingSleeper::default(),
            ProviderBudget::new(1_000, 1_000),
            policy(),
            4663,
        );
        assert_eq!(reader.validate_chain_id().is_ok(), expected_ok);
    }
}

#[test]
fn rejects_disabled_base_chain() {
    let backend = MockHttp {
        responses: RefCell::new(VecDeque::from([Ok(HttpResponse {
            result: json!("0x2105"),
            response_bytes: 10,
        })])),
        requests: Rc::default(),
    };
    let reader = ChainReader::new(
        backend,
        RecordingSleeper::default(),
        ProviderBudget::new(1_000, 1_000),
        policy(),
        4663,
    );
    assert!(matches!(
        reader.validate_chain_id(),
        Err(TransportError::WrongChain(8453))
    ));
}

#[test]
fn retries_transient_http_errors_with_capped_backoff() {
    let backend = MockHttp {
        responses: RefCell::new(VecDeque::from([
            Err(TransportError::Transient("one".to_owned())),
            Err(TransportError::Transient("two".to_owned())),
            Err(TransportError::Transient("three".to_owned())),
            Ok(HttpResponse {
                result: json!("0x1237"),
                response_bytes: 10,
            }),
        ])),
        requests: Rc::default(),
    };
    let sleeper = RecordingSleeper::default();
    let delays = Rc::clone(&sleeper.0);
    let budget = ProviderBudget::new(1_000, 1_000);
    let reader = ChainReader::new(backend, sleeper, budget.clone(), policy(), 4663);
    reader.validate_chain_id().unwrap();
    assert_eq!(
        *delays.borrow(),
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(250)
        ]
    );
    assert_eq!(budget.snapshot().request_cu, 40);
}

#[test]
fn chunks_logs_by_ten_blocks_with_explicit_filters() {
    let requests = Rc::new(RefCell::new(Vec::new()));
    let backend = MockHttp {
        responses: RefCell::new(VecDeque::from([
            Ok(HttpResponse {
                result: json!([]),
                response_bytes: 2,
            }),
            Ok(HttpResponse {
                result: json!([]),
                response_bytes: 2,
            }),
            Ok(HttpResponse {
                result: json!([]),
                response_bytes: 2,
            }),
        ])),
        requests: Rc::clone(&requests),
    };
    let reader = ChainReader::new(
        backend,
        RecordingSleeper::default(),
        ProviderBudget::new(1_000, 1_000),
        policy(),
        4663,
    );
    let address = Address::repeat_byte(1);
    reader
        .get_logs(&LogFilter {
            from_block: 10,
            to_block: 34,
            addresses: vec![address],
            topic0: sync_topic(),
            topic0_alternates: Vec::new(),
        })
        .unwrap();
    let requests = requests.borrow();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].params[0]["fromBlock"], "0xa");
    assert_eq!(requests[0].params[0]["toBlock"], "0x13");
    assert_eq!(requests[2].params[0]["toBlock"], "0x22");
    assert_eq!(requests[0].params[0]["address"][0], json!(address));
    assert_eq!(requests[0].params[0]["topics"][0], json!(sync_topic()));
}

#[test]
fn subscription_is_address_and_derived_topic_filtered() {
    let filter = SubscriptionFilter {
        addresses: vec![Address::repeat_byte(1), Address::repeat_byte(2)],
        topic0: sync_topic(),
    };
    let request = filter.request().unwrap();
    assert_eq!(request[0], "logs");
    assert_eq!(request[1]["address"].as_array().unwrap().len(), 2);
    assert_eq!(request[1]["topics"][0], json!(sync_topic()));
    assert_eq!(
        sync_topic(),
        alloy_primitives::keccak256("Sync(uint112,uint112)")
    );
    assert!(
        SubscriptionFilter {
            addresses: Vec::new(),
            topic0: sync_topic(),
        }
        .request()
        .is_err()
    );
}

fn log_message() -> String {
    json!({
        "params": { "result": {
            "address": Address::repeat_byte(1),
            "topics": [sync_topic()],
            "data": "0x0102",
            "blockNumber": "0x10",
            "transactionIndex": "0x2",
            "logIndex": "0x3",
            "removed": false
        }}
    })
    .to_string()
}

#[test]
fn stream_preserves_duplicates_and_marks_clean_and_dirty_disconnects() {
    let stream = LogStream::new(ProviderBudget::new(1_000, 100_000));
    let payload = log_message();
    assert_eq!(
        stream.message(&payload).unwrap(),
        stream.message(&payload).unwrap()
    );
    assert_eq!(
        LogStream::disconnected(true),
        StreamItem::Disconnected(DisconnectKind::Clean)
    );
    assert_eq!(
        LogStream::disconnected(false),
        StreamItem::Disconnected(DisconnectKind::Dirty)
    );
}

#[test]
fn provider_urls_never_render_secrets() {
    let secret = "https://base.example/v2/secret-api-key";
    let url = RedactedUrl::from_str(secret).unwrap();
    for rendered in [format!("{url:?}"), url.to_string()] {
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("secret-api-key"));
    }
}

#[test]
fn budgets_refuse_at_ceiling_and_report_separate_usage() {
    let budget = ProviderBudget::new(60, 12);
    assert!(matches!(
        budget.charge_http("eth_getLogs", 7),
        Err(BudgetExceeded::RequestCu { ceiling: 60 })
    ));
    assert!(matches!(
        budget.charge_ws_message(10),
        Err(BudgetExceeded::WebSocketBytes { ceiling: 12 })
    ));

    let budget = ProviderBudget::new(100, 100);
    budget.charge_http("eth_call", 7).unwrap();
    budget.charge_ws_message(10).unwrap();
    let usage = budget.snapshot();
    assert_eq!(usage.request_cu, 26);
    assert_eq!(usage.http_response_bytes, 7);
    assert_eq!(usage.websocket_delivered_bytes, 10);
    assert_eq!(usage.websocket_accounted_bytes, 12);
}
