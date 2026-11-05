mod common;

use common::fixtures::*;

#[test]
fn pattern_vectors() {
    let v = load_pattern_vectors().expect("load pattern-vectors.json");
    assert!(!v.cases.is_empty(), "pattern-vectors.json has no cases");
    for c in &v.cases {
        let got = mcp_jack::syntax::match_pattern(&c.pattern, &c.input);
        assert!(
            got == c.matched,
            "case {}: pattern {:?} input {:?}: got {}, want {}",
            c.id,
            c.pattern,
            c.input,
            got,
            c.matched
        );
    }
}
