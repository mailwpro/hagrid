use reqwest::Url;
use reqwest::blocking::Client;
use anyhow::Result;
use reqwest::StatusCode;

static SERVER_URL: &str = "https://keys.openpgp.org";

fn assert_request(client: &Client, url: Url, status: StatusCode) -> Result<()> {
    let response = client.head(url)
        .send()?;
    assert_eq!(response.status(), status);
    Ok(())
}

#[test]
fn vks_by_fingerprint() -> Result<()> {
    let client = Client::new();

    let endpoint = Url::parse(SERVER_URL)?
        .join("/vks/v1/by-fingerprint/")?;

    let nora_primary = "379D09E0A09685C48312D46E9F4EE06E0E229F37";
    assert_request(&client, endpoint.join(nora_primary)?, StatusCode::OK)?;
    let too_short = "379D09E0A09685C48312";
    assert_request(&client, endpoint.join(too_short)?, StatusCode::NOT_FOUND)?;
    let too_long = "379D09E0A09685C48312D46E9F4EE06E0E229F37ABC";
    assert_request(&client, endpoint.join(too_long)?, StatusCode::NOT_FOUND)?;
    let improbable = "1111111111111111111111111111111111111111";
    assert_request(&client, endpoint.join(improbable)?, StatusCode::NOT_FOUND)?;
    // XXX: Api docs say "MUST NOT be prefixed with 0x", but this succeeds
    let with_0x = "0x379D09E0A09685C48312D46E9F4EE06E0E229F37";
    assert_request(&client, endpoint.join(with_0x)?, StatusCode::OK)?;
    let lowercase = "379d09e0a09685c48312d46e9f4ee06e0e229f37";
    assert_request(&client, endpoint.join(lowercase)?, StatusCode::NOT_FOUND)?;
    // XXX: query by subkey
    Ok(())
}

#[test]
fn vks_by_keyid() -> Result<()> {
    let client = Client::new();

    let endpoint = Url::parse(SERVER_URL)?
        .join("/vks/v1/by-keyid/")?;

    let nora_primary = "9F4EE06E0E229F37";
    assert_request(&client, endpoint.join(nora_primary)?, StatusCode::OK)?;
    let too_short = "9F4EE06E0E229F";
    assert_request(&client, endpoint.join(too_short)?, StatusCode::NOT_FOUND)?;
    let too_long = "379D09E0A09685C48312D46E9F4EE06E0E229F37";
    assert_request(&client, endpoint.join(too_long)?, StatusCode::NOT_FOUND)?;
    let improbable = "1111111111111111";
    assert_request(&client, endpoint.join(improbable)?, StatusCode::NOT_FOUND)?;
    // XXX: Api docs say "MUST NOT be prefixed with 0x", but this succeeds
    let with_0x = "0x9F4EE06E0E229F37";
    assert_request(&client, endpoint.join(with_0x)?, StatusCode::OK)?;
    let lowercase = "9f4ee06e0e229f37";
    assert_request(&client, endpoint.join(lowercase)?, StatusCode::NOT_FOUND)?;
    // XXX: query by subkey
    Ok(())
}

#[test]
fn vks_by_email() -> Result<()> {
    let client = Client::new();

    let endpoint = Url::parse(SERVER_URL)?
        .join("/vks/v1/by-email/")?;

    let nora = "nora@sequoia-pgp.org";
    assert_request(&client, endpoint.join(nora)?, StatusCode::OK)?;
    Ok(())
}
