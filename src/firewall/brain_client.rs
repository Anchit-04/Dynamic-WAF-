use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize)]
struct BrainRequest {
    payload: String,
}

#[derive(Deserialize)]
struct BrainResponse {
    #[allow(dead_code)]
    score: f32,
    action: String,
    #[allow(dead_code)]
    threshold: f32,
}

pub struct BrainClient {
    http_client: Client,
    api_url: String,
}

impl BrainClient {
    pub fn new(api_url: &str) -> Self {
        BrainClient {
            http_client: Client::builder()
                .timeout(Duration::from_millis(500)) // Safety: Don't wait more than 500ms for AI
                .build()
                .unwrap(),
            api_url: api_url.to_string(),
        }
    }

    /// Sends the payload to the Transformer Brain (Layer 2)
    pub async fn analyze(&self, payload: &str) -> bool {
        let request_body = BrainRequest {
            payload: payload.to_string(),
        };

        let response = self.http_client
            .post(&self.api_url)
            .json(&request_body)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status() == StatusCode::OK => {
                if let Ok(data) = resp.json::<BrainResponse>().await {
                    // Return true if the Brain says "block"
                    return data.action == "block";
                }
                false
            }
            _ => {
                // Production Fail-Safe: If the Brain is down, let the traffic through 
                // (Layer 1 already caught the obvious stuff)
                println!("[WARN] Brain Layer unreachable. Defaulting to PASS.");
                false
            }
        }
    }
}