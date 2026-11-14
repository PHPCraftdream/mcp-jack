// Дифференциальный corpus rust/tests/rotation-property-corpus.json; TS-twin —
// ts/test/rotation-property-corpus.test.ts. Обе реализации обязаны совпадать.
use mcp_jack::encoding::decode_b64url_fixed;
use mcp_jack::rotation::{self, DecodedResult, ResultCursor};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgumentCase {
    id: String,
    text: String,
    accept: bool,
    ordinal: Option<u64>,
    hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultCase {
    id: String,
    id_json: String,
    body: String,
    accept: bool,
    kid: Option<String>,
    public_key: Option<String>,
    records: Option<Vec<String>>,
    head_ordinal: Option<u64>,
    head_hash: Option<String>,
    complete: Option<bool>,
}

// note/anchor_public_key/other_kid/cursor_hash_trailing_bits сознательно не читаются.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    format: String,
    note: String,
    anchor_kid: String,
    anchor_public_key: String,
    other_kid: String,
    cursor_hash: String,
    cursor_hash_trailing_bits: String,
    server_key_arguments: Vec<ArgumentCase>,
    result_bodies: Vec<ResultCase>,
}

fn corpus() -> Corpus {
    serde_json::from_str(include_str!("rotation-property-corpus.json")).expect("typed corpus")
}

fn expected_cursor(case: &ArgumentCase) -> ResultCursor {
    let (ordinal, hash) = match (case.ordinal, case.hash.as_ref()) {
        (Some(ordinal), Some(hash)) => (ordinal, hash),
        _ => panic!("accepted arguments case {} lacks expectations", case.id),
    };
    ResultCursor {
        ordinal,
        hash: hash.clone(),
    }
}

fn expected_result(case: &ResultCase) -> DecodedResult {
    let (kid, public_key, records, head_ordinal, head_hash, complete) = match (
        case.kid.as_ref(),
        case.public_key.as_ref(),
        case.records.as_ref(),
        case.head_ordinal,
        case.head_hash.as_ref(),
        case.complete,
    ) {
        (
            Some(kid),
            Some(public_key),
            Some(records),
            Some(head_ordinal),
            Some(head_hash),
            Some(complete),
        ) => (kid, public_key, records, head_ordinal, head_hash, complete),
        _ => panic!("accepted result case {} lacks expectations", case.id),
    };
    DecodedResult {
        current_kid: kid.clone(),
        current_public_key: decode_b64url_fixed(public_key, 32)
            .expect("corpus public key")
            .try_into()
            .expect("32 bytes"),
        records: records.clone(),
        head_ordinal,
        head_hash: head_hash.clone(),
        complete,
    }
}

#[test]
fn differential_corpus_is_well_formed_and_sized() {
    let corpus = corpus();
    assert_eq!(corpus.format, "mcp-jack-rotation-property-corpus-v1");
    assert_eq!(corpus.server_key_arguments.len(), 50);
    assert_eq!(corpus.result_bodies.len(), 33);
    assert_eq!(
        corpus
            .server_key_arguments
            .iter()
            .filter(|case| case.accept)
            .count(),
        9
    );
    assert_eq!(
        corpus
            .server_key_arguments
            .iter()
            .filter(|case| !case.accept)
            .count(),
        41
    );
    assert_eq!(
        corpus.result_bodies.iter().filter(|case| case.accept).count(),
        8
    );
    assert_eq!(
        corpus
            .result_bodies
            .iter()
            .filter(|case| !case.accept)
            .count(),
        25
    );
    assert_eq!(corpus.anchor_kid.len(), 43);
    assert_eq!(corpus.cursor_hash.len(), 43);
}

#[test]
fn server_key_arguments_match_the_shared_corpus() {
    let corpus = corpus();
    for case in &corpus.server_key_arguments {
        let decoded = rotation::decode_server_key_arguments(case.text.as_bytes());
        if case.accept {
            let label = format!("accepted arguments case {}", case.id);
            let cursor = decoded.expect(&label);
            let expected = expected_cursor(case);
            assert_eq!(cursor.ordinal, expected.ordinal, "{}", case.id);
            assert_eq!(cursor.hash, expected.hash, "{}", case.id);
        } else {
            let label = format!("rejected arguments case {}", case.id);
            let error = decoded.expect_err(&label);
            assert_eq!(error.code, "invalid_params", "{}", case.id);
        }
    }
}

#[test]
fn rotation_result_decoding_matches_the_shared_corpus() {
    let corpus = corpus();
    for case in &corpus.result_bodies {
        let decoded = rotation::decode_result(case.body.as_bytes(), case.id_json.as_bytes());
        if case.accept {
            let label = format!("accepted result case {}", case.id);
            assert_eq!(decoded.expect(&label), expected_result(case));
        } else {
            let label = format!("rejected result case {}", case.id);
            let error = decoded.expect_err(&label);
            assert_eq!(error.code, "rotation_result_invalid", "{}", case.id);
        }
    }
}
