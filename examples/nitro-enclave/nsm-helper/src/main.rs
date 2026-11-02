// CooL
// Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// The NSM helper for CooL's `CommandNsmSource` (src/nitro/receipt.ts).
//
// Contract: read ONE JSON object from stdin
//     {"nonce": <base64|null>, "user_data": <base64|null>, "public_key": <base64|null>}
// ask the Nitro Secure Module (/dev/nsm) for an attestation document carrying
// exactly those fields, and print the document (COSE_Sign1, CBOR) as base64 on
// stdout. Any failure: a message on stderr and a non-zero exit — never a
// partial or empty document on stdout.
//
// Runs only inside a Nitro Enclave; /dev/nsm does not exist anywhere else.

use std::io::{self, Read, Write};

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_bytes::ByteBuf;

#[derive(Deserialize)]
struct Input {
    nonce: Option<String>,
    user_data: Option<String>,
    public_key: Option<String>,
}

// NSM limits per field (aws-nitro-enclaves-nsm-api): 512 bytes nonce, 512 user_data, 1024 public_key.
fn field(name: &str, v: Option<String>, max: usize) -> Result<Option<ByteBuf>, String> {
    match v {
        None => Ok(None),
        Some(s) => {
            let b = B64.decode(s.as_bytes()).map_err(|e| format!("{name}: invalid base64: {e}"))?;
            if b.len() > max {
                return Err(format!("{name}: {} bytes exceeds the NSM limit of {max}", b.len()));
            }
            Ok(Some(ByteBuf::from(b)))
        }
    }
}

fn run() -> Result<String, String> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw).map_err(|e| format!("stdin: {e}"))?;
    let input: Input = serde_json::from_str(&raw).map_err(|e| format!("stdin is not the expected JSON: {e}"))?;
    let request = Request::Attestation {
        nonce: field("nonce", input.nonce, 512)?,
        user_data: field("user_data", input.user_data, 512)?,
        public_key: field("public_key", input.public_key, 1024)?,
    };
    let fd = nsm_init();
    if fd < 0 {
        return Err("cannot open /dev/nsm: is this running inside a Nitro Enclave?".into());
    }
    let response = nsm_process_request(fd, request);
    nsm_exit(fd);
    match response {
        Response::Attestation { document } if !document.is_empty() => Ok(B64.encode(document)),
        Response::Attestation { .. } => Err("the NSM returned an empty document".into()),
        Response::Error(code) => Err(format!("the NSM refused the request: {code:?}")),
        other => Err(format!("unexpected NSM response: {other:?}")),
    }
}

fn main() {
    match run() {
        Ok(doc) => {
            let mut out = io::stdout().lock();
            if writeln!(out, "{doc}").is_err() {
                std::process::exit(3);
            }
        }
        Err(msg) => {
            eprintln!("cool-nsm-helper: {msg}");
            std::process::exit(1);
        }
    }
}
