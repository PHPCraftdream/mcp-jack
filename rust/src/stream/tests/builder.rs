//! Builder tests: the byte-exact open header and frame chain of
//! `spec/fixtures/modern/stream-build-vectors.json`, `resume` and a refusing
//! signer.

use ed25519_dalek::SigningKey;

use crate::encoding::decode_b64url;
use crate::stream::{SignedFrame, StaticStreamSigner, StreamBuilder, StreamSigner};

// TEST ONLY: spec/fixtures/keys.json ("svc").
const SEED_HEX: &str = "cc9e39e830a43e09c6372b14852ef80a2bb8e7b1aa4c04bf076f33e0aad2c901";
const KID: &str = "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88";
const REQUEST_SIG: &str =
    "OsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw";
const SID: &str = "q9nUNYuH-Xf_cgJBVu4_Dg";
const OPEN_TS: i64 = 1767225600;
const STATUS: u16 = 200;

// Every case signs the same open header, so these values are shared.
const OPEN_JACK_AUTH: &str = "s1 kid=wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88,ts=1767225600,sid=q9nUNYuH-Xf_cgJBVu4_Dg,sig=LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ";
const OPEN_SIGNING_STRING: &str = r#"mcp-jack/stream1/open
200
OsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw
wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88
1767225600
q9nUNYuH-Xf_cgJBVu4_Dg"#;

struct FrameCase {
    seq: u64,
    ts: i64,
    prev: &'static str,
    data_hash: &'static str,
    signing_string: &'static str,
    sig: &'static str,
}

struct Case {
    id: &'static str,
    input: &'static [(u64, i64, &'static str)],
    expect: &'static [FrameCase],
    stream_b64u: &'static str,
}

const CASES: &[Case] = &[
    Case {
        id: "build-open",
        input: &[],
        expect: &[],
        stream_b64u: "",
    },
    Case {
        id: "build-only-end",
        input: &[(0, 1767225601, "")],
        expect: &[FrameCase {
            seq: 0,
            ts: 1767225601,
            prev: "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ",
            data_hash: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
0
1767225601
LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ
47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"#,
            sig: "cRUEuo0_hPa1Ezbe9xaS_iD0Qxwvhcap2I8EwbN3pjx4MjHoPwyUOBf9KtO3k0vQyiRXSh6g3Zt_tXzyu9g9Bg",
        }],
        stream_b64u: "ZXZlbnQ6IGphY2stZW5kCmRhdGE6CmphY2s6IHNlcT0wLHRzPTE3NjcyMjU2MDEsc2lnPWNSVUV1bzBfaFBhMUV6YmU5eGFTX2lEMFF4d3ZoY2FwMkk4RXdiTjNwang0TWpIb1B3eVVPQmY5S3RPM2swdlF5aVJYU2g2ZzNadF90WHp5dTlnOUJnCgo",
    },
    Case {
        id: "build-single-frame",
        input: &[
            (0, 1767225600, r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1}}"#),
            (1, 1767225601, ""),
        ],
        expect: &[
            FrameCase {
                seq: 0,
                ts: 1767225600,
                prev: "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ",
                data_hash: "rVg4DOHW6fi-h59KsRCty9PJOInK-PMMWYss-o4rGzc",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
0
1767225600
LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ
rVg4DOHW6fi-h59KsRCty9PJOInK-PMMWYss-o4rGzc"#,
                sig: "urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA",
            },
            FrameCase {
                seq: 1,
                ts: 1767225601,
                prev: "urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA",
                data_hash: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
1
1767225601
urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA
47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"#,
                sig: "Uco3e3YKijC13IJkAbQHalmefZEb7muzlyKWR8_jcvwVRYJMk4YIfqYSZO92HBXVwcaxmtiCO0HoHLObslZjBA",
            },
        ],
        stream_b64u: "ZXZlbnQ6IG1lc3NhZ2UKZGF0YTogeyJqc29ucnBjIjoiMi4wIiwibWV0aG9kIjoibm90aWZpY2F0aW9ucy9wcm9ncmVzcyIsInBhcmFtcyI6eyJwcm9ncmVzc1Rva2VuIjoidDEiLCJwcm9ncmVzcyI6MX19CmphY2s6IHNlcT0wLHRzPTE3NjcyMjU2MDAsc2lnPXVycERmZ09OOUxmSEVPNXhJdGJlQmpsNlRZMXd3VlpFcTEzemJGMUxzcXd5ZG81R2ZCbTZIUkFZLUpMa296S0U0dnlydFBVeTlpMF9xNDNyMnR1N0RBCgpldmVudDogamFjay1lbmQKZGF0YToKamFjazogc2VxPTEsdHM9MTc2NzIyNTYwMSxzaWc9VWNvM2UzWUtpakMxM0lKa0FiUUhhbG1lZlpFYjdtdXpseUtXUjhfamN2d1ZSWUpNazRZSWZxWVNaTzkySEJYVndjYXhtdGlDTzBIb0hMT2JzbFpqQkEKCg",
    },
    Case {
        id: "build-three-frames",
        input: &[
            (0, 1767225600, r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1}}"#),
            (1, 1767225601, r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":2}}"#),
            (2, 1767225602, r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#),
            (3, 1767225603, ""),
        ],
        expect: &[
            FrameCase {
                seq: 0,
                ts: 1767225600,
                prev: "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ",
                data_hash: "rVg4DOHW6fi-h59KsRCty9PJOInK-PMMWYss-o4rGzc",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
0
1767225600
LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ
rVg4DOHW6fi-h59KsRCty9PJOInK-PMMWYss-o4rGzc"#,
                sig: "urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA",
            },
            FrameCase {
                seq: 1,
                ts: 1767225601,
                prev: "urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA",
                data_hash: "0KvwkncG3XfkBApATzbYuxZ5WtYrhwHz3HpkHgIrWik",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
1
1767225601
urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA
0KvwkncG3XfkBApATzbYuxZ5WtYrhwHz3HpkHgIrWik"#,
                sig: "AwAnUxkzPpeJA0p9YwsL8ebTjlTdHqxTFyFkPGf3oPzwHGzzvaEvrG01vnx3I4t_InAa2Qqgrp5STqdRy6mZAw",
            },
            FrameCase {
                seq: 2,
                ts: 1767225602,
                prev: "AwAnUxkzPpeJA0p9YwsL8ebTjlTdHqxTFyFkPGf3oPzwHGzzvaEvrG01vnx3I4t_InAa2Qqgrp5STqdRy6mZAw",
                data_hash: "PLmCCbhIGTbodedGJIp_2YqtcClkVqao_wV9iTJFA-U",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
2
1767225602
AwAnUxkzPpeJA0p9YwsL8ebTjlTdHqxTFyFkPGf3oPzwHGzzvaEvrG01vnx3I4t_InAa2Qqgrp5STqdRy6mZAw
PLmCCbhIGTbodedGJIp_2YqtcClkVqao_wV9iTJFA-U"#,
                sig: "_mcIemEB5KLOf2FwK3PzMp_H-3TYInYqm6aW3DrHd-6q11YSxghquwfWlIF8NN0jc9tG58yY6GfKDRcncgUPAw",
            },
            FrameCase {
                seq: 3,
                ts: 1767225603,
                prev: "_mcIemEB5KLOf2FwK3PzMp_H-3TYInYqm6aW3DrHd-6q11YSxghquwfWlIF8NN0jc9tG58yY6GfKDRcncgUPAw",
                data_hash: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
3
1767225603
_mcIemEB5KLOf2FwK3PzMp_H-3TYInYqm6aW3DrHd-6q11YSxghquwfWlIF8NN0jc9tG58yY6GfKDRcncgUPAw
47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"#,
                sig: "DLfTFfQf2UJnNEaddG19fd_ouF3fZx9mfuUo7F5xVhjCPz_XFWwNFLB7yxgLHaCO3gNdR6rTsInB5PKbke3RBg",
            },
        ],
        stream_b64u: "ZXZlbnQ6IG1lc3NhZ2UKZGF0YTogeyJqc29ucnBjIjoiMi4wIiwibWV0aG9kIjoibm90aWZpY2F0aW9ucy9wcm9ncmVzcyIsInBhcmFtcyI6eyJwcm9ncmVzc1Rva2VuIjoidDEiLCJwcm9ncmVzcyI6MX19CmphY2s6IHNlcT0wLHRzPTE3NjcyMjU2MDAsc2lnPXVycERmZ09OOUxmSEVPNXhJdGJlQmpsNlRZMXd3VlpFcTEzemJGMUxzcXd5ZG81R2ZCbTZIUkFZLUpMa296S0U0dnlydFBVeTlpMF9xNDNyMnR1N0RBCgpldmVudDogbWVzc2FnZQpkYXRhOiB7Impzb25ycGMiOiIyLjAiLCJtZXRob2QiOiJub3RpZmljYXRpb25zL3Byb2dyZXNzIiwicGFyYW1zIjp7InByb2dyZXNzVG9rZW4iOiJ0MSIsInByb2dyZXNzIjoyfX0KamFjazogc2VxPTEsdHM9MTc2NzIyNTYwMSxzaWc9QXdBblV4a3pQcGVKQTBwOVl3c0w4ZWJUamxUZEhxeFRGeUZrUEdmM29QendIR3p6dmFFdnJHMDF2bngzSTR0X0luQWEyUXFncnA1U1RxZFJ5Nm1aQXcKCmV2ZW50OiBtZXNzYWdlCmRhdGE6IHsianNvbnJwYyI6IjIuMCIsImlkIjoxLCJyZXN1bHQiOnsib2siOnRydWV9fQpqYWNrOiBzZXE9Mix0cz0xNzY3MjI1NjAyLHNpZz1fbWNJZW1FQjVLTE9mMkZ3SzNQek1wX0gtM1RZSW5ZcW02YVczRHJIZC02cTExWVN4Z2hxdXdmV2xJRjhOTjBqYzl0RzU4eVk2R2ZLRFJjbmNnVVBBdwoKZXZlbnQ6IGphY2stZW5kCmRhdGE6CmphY2s6IHNlcT0zLHRzPTE3NjcyMjU2MDMsc2lnPURMZlRGZlFmMlVKbk5FYWRkRzE5ZmRfb3VGM2ZaeDltZnVVbzdGNXhWaGpDUHpfWEZXd05GTEI3eXhnTEhhQ08zZ05kUjZyVHNJbkI1UEtia2UzUkJnCgo",
    },
    Case {
        id: "build-multiline",
        input: &[
            (0, 1767225600, "{\n  \"jsonrpc\": \"2.0\",\n  \"method\": \"notifications/message\",\n  \"params\": {\"data\": \"multi\"}\n}"),
            (1, 1767225601, ""),
        ],
        expect: &[
            FrameCase {
                seq: 0,
                ts: 1767225600,
                prev: "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ",
                data_hash: "3aJZU1bGVyEDwSO4HdFAUup9rWlDPQBV-Egh0bF9Uls",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
0
1767225600
LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ
3aJZU1bGVyEDwSO4HdFAUup9rWlDPQBV-Egh0bF9Uls"#,
                sig: "YFBaZCE7EFvha3zpGFC0CGfoSiJHrAOfCv2abn4SMS1lx_LbbLnmpXTIpAK5Lgd0oOmFKnzwXAACKsw3lWBmBQ",
            },
            FrameCase {
                seq: 1,
                ts: 1767225601,
                prev: "YFBaZCE7EFvha3zpGFC0CGfoSiJHrAOfCv2abn4SMS1lx_LbbLnmpXTIpAK5Lgd0oOmFKnzwXAACKsw3lWBmBQ",
                data_hash: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
1
1767225601
YFBaZCE7EFvha3zpGFC0CGfoSiJHrAOfCv2abn4SMS1lx_LbbLnmpXTIpAK5Lgd0oOmFKnzwXAACKsw3lWBmBQ
47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"#,
                sig: "zkBSBzs4bPqv9MrzZZQzovtw17QESaaAqC_OtRYlmfDil4Rr3bZ6LFqaWmfQ3_axQzqC0JhbnLLgf6G6xo2fCA",
            },
        ],
        stream_b64u: "ZXZlbnQ6IG1lc3NhZ2UKZGF0YTogewpkYXRhOiAgICJqc29ucnBjIjogIjIuMCIsCmRhdGE6ICAgIm1ldGhvZCI6ICJub3RpZmljYXRpb25zL21lc3NhZ2UiLApkYXRhOiAgICJwYXJhbXMiOiB7ImRhdGEiOiAibXVsdGkifQpkYXRhOiB9CmphY2s6IHNlcT0wLHRzPTE3NjcyMjU2MDAsc2lnPVlGQmFaQ0U3RUZ2aGEzenBHRkMwQ0dmb1NpSkhyQU9mQ3YyYWJuNFNNUzFseF9MYmJMbm1wWFRJcEFLNUxnZDBvT21GS256d1hBQUNLc3czbFdCbUJRCgpldmVudDogamFjay1lbmQKZGF0YToKamFjazogc2VxPTEsdHM9MTc2NzIyNTYwMSxzaWc9emtCU0J6czRiUHF2OU1yelpaUXpvdnR3MTdRRVNhYUFxQ19PdFJZbG1mRGlsNFJyM2JaNkxGcWFXbWZRM19heFF6cUMwSmhibkxMZ2Y2RzZ4bzJmQ0EKCg",
    },
    Case {
        id: "build-unicode",
        input: &[
            (0, 1767225600, r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"café 漢字"}}"#),
            (1, 1767225601, ""),
        ],
        expect: &[
            FrameCase {
                seq: 0,
                ts: 1767225600,
                prev: "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ",
                data_hash: "wDo8JIIttV3HshNMhJnLnXujwS-eQh1JG5gQcOnN-VA",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
0
1767225600
LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ
wDo8JIIttV3HshNMhJnLnXujwS-eQh1JG5gQcOnN-VA"#,
                sig: "2x0cyOlPlnUy-7p4_f8XcCD5eIx7BXNs18LUSaFj2RMA135naicMG5juhDKUwuddwy0HyL23HiaVOvhe7RWrCA",
            },
            FrameCase {
                seq: 1,
                ts: 1767225601,
                prev: "2x0cyOlPlnUy-7p4_f8XcCD5eIx7BXNs18LUSaFj2RMA135naicMG5juhDKUwuddwy0HyL23HiaVOvhe7RWrCA",
                data_hash: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
1
1767225601
2x0cyOlPlnUy-7p4_f8XcCD5eIx7BXNs18LUSaFj2RMA135naicMG5juhDKUwuddwy0HyL23HiaVOvhe7RWrCA
47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"#,
                sig: "GWb3o_DZh0KaWdxgoniqQ0mtPnY3FT-hdBNhjIsrJgZkTH9BTEpQxBn6Q-ioHaqkwAWvyn-it3XhnL21JKaYBw",
            },
        ],
        stream_b64u: "ZXZlbnQ6IG1lc3NhZ2UKZGF0YTogeyJqc29ucnBjIjoiMi4wIiwibWV0aG9kIjoibm90aWZpY2F0aW9ucy9tZXNzYWdlIiwicGFyYW1zIjp7ImRhdGEiOiJjYWbDqSDmvKLlrZcifX0KamFjazogc2VxPTAsdHM9MTc2NzIyNTYwMCxzaWc9MngwY3lPbFBsblV5LTdwNF9mOFhjQ0Q1ZUl4N0JYTnMxOExVU2FGajJSTUExMzVuYWljTUc1anVoREtVd3VkZHd5MEh5TDIzSGlhVk92aGU3UldyQ0EKCmV2ZW50OiBqYWNrLWVuZApkYXRhOgpqYWNrOiBzZXE9MSx0cz0xNzY3MjI1NjAxLHNpZz1HV2Izb19EWmgwS2FXZHhnb25pcVEwbXRQblkzRlQtaGRCTmhqSXNySmdaa1RIOUJURXBReEJuNlEtaW9IYXFrd0FXdnluLWl0M1hobkwyMUpLYVlCdwoK",
    },
    Case {
        id: "build-oversize-error-frame",
        input: &[
            (0, 1767225600, r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1024}}"#),
            (1, 1767225601, ""),
        ],
        expect: &[
            FrameCase {
                seq: 0,
                ts: 1767225600,
                prev: "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ",
                data_hash: "nJEiDoDCprjxfkGRi_-p8IHxdJg10J39JBDzr71JaUs",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
0
1767225600
LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ
nJEiDoDCprjxfkGRi_-p8IHxdJg10J39JBDzr71JaUs"#,
                sig: "UoVHefeLbN-Xm2hD7nA5M8p0sSLA83JM9dUzlOHN3T3bIGV_0Xou_yLg2Nw9skxtk0kFMDl_0ADvZXL92VNyAw",
            },
            FrameCase {
                seq: 1,
                ts: 1767225601,
                prev: "UoVHefeLbN-Xm2hD7nA5M8p0sSLA83JM9dUzlOHN3T3bIGV_0Xou_yLg2Nw9skxtk0kFMDl_0ADvZXL92VNyAw",
                data_hash: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
1
1767225601
UoVHefeLbN-Xm2hD7nA5M8p0sSLA83JM9dUzlOHN3T3bIGV_0Xou_yLg2Nw9skxtk0kFMDl_0ADvZXL92VNyAw
47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"#,
                sig: "Dj5W8MW2iG3mKVPhkLKDNVgTY2hJw8311EbUhAuXiqZRh6JmoC1MZmwOxokwaOz_65MiTXjHzp9m3yVAeELKCQ",
            },
        ],
        stream_b64u: "ZXZlbnQ6IG1lc3NhZ2UKZGF0YTogeyJqc29ucnBjIjoiMi4wIiwibWV0aG9kIjoibm90aWZpY2F0aW9ucy9qYWNrL3N0cmVhbV9lcnJvciIsInBhcmFtcyI6eyJjb2RlIjoic3RyZWFtX2ZyYW1lX3Rvb19sYXJnZSIsImxpbWl0IjoxMDI0fX0KamFjazogc2VxPTAsdHM9MTc2NzIyNTYwMCxzaWc9VW9WSGVmZUxiTi1YbTJoRDduQTVNOHAwc1NMQTgzSk05ZFV6bE9ITjNUM2JJR1ZfMFhvdV95TGcyTnc5c2t4dGswa0ZNRGxfMEFEdlpYTDkyVk55QXcKCmV2ZW50OiBqYWNrLWVuZApkYXRhOgpqYWNrOiBzZXE9MSx0cz0xNzY3MjI1NjAxLHNpZz1EajVXOE1XMmlHM21LVlBoa0xLRE5WZ1RZMmhKdzgzMTFFYlVoQXVYaXFaUmg2Sm1vQzFNWm13T3hva3dhT3pfNjVNaVRYakh6cDltM3lWQWVFTEtDUQoK",
    },
    Case {
        id: "build-long-ts",
        input: &[
            (0, 1767225600, r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1}}"#),
            (1, 1767225700, r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":2}}"#),
            (2, 1767225800, r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":3}}"#),
            (3, 1767225800, ""),
        ],
        expect: &[
            FrameCase {
                seq: 0,
                ts: 1767225600,
                prev: "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ",
                data_hash: "rVg4DOHW6fi-h59KsRCty9PJOInK-PMMWYss-o4rGzc",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
0
1767225600
LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ
rVg4DOHW6fi-h59KsRCty9PJOInK-PMMWYss-o4rGzc"#,
                sig: "urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA",
            },
            FrameCase {
                seq: 1,
                ts: 1767225700,
                prev: "urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA",
                data_hash: "0KvwkncG3XfkBApATzbYuxZ5WtYrhwHz3HpkHgIrWik",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
1
1767225700
urpDfgON9LfHEO5xItbeBjl6TY1wwVZEq13zbF1Lsqwydo5GfBm6HRAY-JLkozKE4vyrtPUy9i0_q43r2tu7DA
0KvwkncG3XfkBApATzbYuxZ5WtYrhwHz3HpkHgIrWik"#,
                sig: "K0ErZhdXCDtH8WGJcfpnCZ1nD4czgAu6eYbssmo8FWjD7BIu4Pm6vA4sLKTddN84pZ1q5bcpo7IIWjtvt3p5Bg",
            },
            FrameCase {
                seq: 2,
                ts: 1767225800,
                prev: "K0ErZhdXCDtH8WGJcfpnCZ1nD4czgAu6eYbssmo8FWjD7BIu4Pm6vA4sLKTddN84pZ1q5bcpo7IIWjtvt3p5Bg",
                data_hash: "vJKdkv5jVsDNkBZgOWyWJIvaX7AwvRx7FTh6QZ_E3hM",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
2
1767225800
K0ErZhdXCDtH8WGJcfpnCZ1nD4czgAu6eYbssmo8FWjD7BIu4Pm6vA4sLKTddN84pZ1q5bcpo7IIWjtvt3p5Bg
vJKdkv5jVsDNkBZgOWyWJIvaX7AwvRx7FTh6QZ_E3hM"#,
                sig: "a2NqFlMYqUH9IoMjQJv6oeRxz06iH0sDgOhHMHDD3ZWw4RjyhAqkZJfvlt1eucnuPkhiCgRIJoqn_EQEzlatCw",
            },
            FrameCase {
                seq: 3,
                ts: 1767225800,
                prev: "a2NqFlMYqUH9IoMjQJv6oeRxz06iH0sDgOhHMHDD3ZWw4RjyhAqkZJfvlt1eucnuPkhiCgRIJoqn_EQEzlatCw",
                data_hash: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
                signing_string: r#"mcp-jack/stream1/frame
q9nUNYuH-Xf_cgJBVu4_Dg
3
1767225800
a2NqFlMYqUH9IoMjQJv6oeRxz06iH0sDgOhHMHDD3ZWw4RjyhAqkZJfvlt1eucnuPkhiCgRIJoqn_EQEzlatCw
47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"#,
                sig: "i7Bk8z5SaKZYg6RXZfeXmwWcxAQZY-T-fsnsIB_P99MfGWj9cXht--_Yn8cEAz99BQWhZH6cCZEEywX8azK5CQ",
            },
        ],
        stream_b64u: "ZXZlbnQ6IG1lc3NhZ2UKZGF0YTogeyJqc29ucnBjIjoiMi4wIiwibWV0aG9kIjoibm90aWZpY2F0aW9ucy9wcm9ncmVzcyIsInBhcmFtcyI6eyJwcm9ncmVzc1Rva2VuIjoidDEiLCJwcm9ncmVzcyI6MX19CmphY2s6IHNlcT0wLHRzPTE3NjcyMjU2MDAsc2lnPXVycERmZ09OOUxmSEVPNXhJdGJlQmpsNlRZMXd3VlpFcTEzemJGMUxzcXd5ZG81R2ZCbTZIUkFZLUpMa296S0U0dnlydFBVeTlpMF9xNDNyMnR1N0RBCgpldmVudDogbWVzc2FnZQpkYXRhOiB7Impzb25ycGMiOiIyLjAiLCJtZXRob2QiOiJub3RpZmljYXRpb25zL3Byb2dyZXNzIiwicGFyYW1zIjp7InByb2dyZXNzVG9rZW4iOiJ0MSIsInByb2dyZXNzIjoyfX0KamFjazogc2VxPTEsdHM9MTc2NzIyNTcwMCxzaWc9SzBFclpoZFhDRHRIOFdHSmNmcG5DWjFuRDRjemdBdTZlWWJzc21vOEZXakQ3Qkl1NFBtNnZBNHNMS1RkZE44NHBaMXE1YmNwbzdJSVdqdHZ0M3A1QmcKCmV2ZW50OiBtZXNzYWdlCmRhdGE6IHsianNvbnJwYyI6IjIuMCIsIm1ldGhvZCI6Im5vdGlmaWNhdGlvbnMvcHJvZ3Jlc3MiLCJwYXJhbXMiOnsicHJvZ3Jlc3NUb2tlbiI6InQxIiwicHJvZ3Jlc3MiOjN9fQpqYWNrOiBzZXE9Mix0cz0xNzY3MjI1ODAwLHNpZz1hMk5xRmxNWXFVSDlJb01qUUp2Nm9lUnh6MDZpSDBzRGdPaEhNSEREM1pXdzRSanloQXFrWkpmdmx0MWV1Y251UGtoaUNnUklKb3FuX0VRRXpsYXRDdwoKZXZlbnQ6IGphY2stZW5kCmRhdGE6CmphY2s6IHNlcT0zLHRzPTE3NjcyMjU4MDAsc2lnPWk3Qms4ejVTYUtaWWc2UlhaZmVYbXdXY3hBUVpZLVQtZnNuc0lCX1A5OU1mR1dqOWNYaHQtLV9ZbjhjRUF6OTlCUVdoWkg2Y0NaRUV5d1g4YXpLNUNRCgo",
    },
];

fn hex_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (index, pair) in SEED_HEX.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).expect("ASCII hex");
        seed[index] = u8::from_str_radix(text, 16).expect("hex byte");
    }
    seed
}

fn signer() -> StaticStreamSigner {
    StaticStreamSigner::new(SigningKey::from_bytes(&hex_seed()), None)
}

fn assert_frame(case: &Case, index: usize, frame: &SignedFrame) {
    let expected = &case.expect[index];
    assert_eq!(frame.seq, expected.seq, "{}: frame {index} seq", case.id);
    assert_eq!(frame.ts, expected.ts, "{}: frame {index} ts", case.id);
    assert_eq!(frame.prev, expected.prev, "{}: frame {index} prev", case.id);
    assert_eq!(
        frame.data_hash, expected.data_hash,
        "{}: frame {index} data_hash",
        case.id
    );
    assert_eq!(
        frame.signing_string, expected.signing_string,
        "{}: frame {index} signing_string",
        case.id
    );
    assert_eq!(frame.sig, expected.sig, "{}: frame {index} sig", case.id);
}

/// Signs every input frame and returns the concatenated wire bytes.
fn sign_case(case: &Case, builder: &mut StreamBuilder) -> String {
    let signer = signer();
    let mut wire = String::new();
    for (index, &(seq, ts, data)) in case.input.iter().enumerate() {
        assert_eq!(builder.seq(), seq, "{}: frame {index} builder seq", case.id);
        let (frame, bytes) = builder
            .frame(ts, data, &signer)
            .unwrap_or_else(|| panic!("{}: frame {index} signed", case.id));
        assert_frame(case, index, &frame);
        wire.push_str(&bytes);
    }
    wire
}

fn assert_wire(case: &Case, wire: &str) {
    let expected = decode_b64url(case.stream_b64u).expect("fixture stream_b64u");
    assert_eq!(
        wire.as_bytes(),
        expected.as_slice(),
        "{}: concatenated wire",
        case.id
    );
}

#[test]
fn build_vectors() {
    let signer = signer();
    assert_eq!(signer.kid(), KID);
    for case in CASES {
        let (mut builder, open) =
            StreamBuilder::open(STATUS, REQUEST_SIG, KID, OPEN_TS, SID, &signer)
                .unwrap_or_else(|| panic!("{}: open header signed", case.id));
        assert_eq!(open.jack_auth, OPEN_JACK_AUTH, "{}: jack_auth", case.id);
        assert_eq!(
            open.signing_string, OPEN_SIGNING_STRING,
            "{}: open signing string",
            case.id
        );
        assert_wire(case, &sign_case(case, &mut builder));
    }
}

#[test]
fn resume_rebuilds_the_same_chain() {
    let signer = signer();
    let open_sig = StreamBuilder::open(STATUS, REQUEST_SIG, KID, OPEN_TS, SID, &signer)
        .expect("open header signed")
        .1
        .sig;
    for case in CASES {
        let mut builder = StreamBuilder::resume(SID, &open_sig);
        assert_eq!(builder.seq(), 0, "{}: resume starts at seq 0", case.id);
        assert_eq!(
            builder.prev(),
            open_sig,
            "{}: resume chains the open",
            case.id
        );
        assert_wire(case, &sign_case(case, &mut builder));
    }
}

/// A signer whose key may no longer sign.
struct Refusing;

impl StreamSigner for Refusing {
    fn sign(&self, _message: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[test]
fn refusing_signer_yields_none_and_keeps_the_chain() {
    let (mut builder, _) =
        StreamBuilder::open(STATUS, REQUEST_SIG, KID, OPEN_TS, SID, &signer()).expect("open");
    assert!(builder.frame(OPEN_TS, "data", &Refusing).is_none());
    assert!(builder.end(OPEN_TS, &Refusing).is_none());
    assert_eq!(builder.seq(), 0);
    assert_eq!(
        builder.prev(),
        "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ"
    );
    assert!(StreamBuilder::open(STATUS, REQUEST_SIG, KID, OPEN_TS, SID, &Refusing).is_none());
}
