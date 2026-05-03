#[macro_use]
extern crate hyperscan;
use async_trait::async_trait;
use pingora::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use bytes::Bytes; // Fixed: Required for body processing

mod firewall;
use firewall::normalize::RequestNormalizer;
use firewall::scanner::Scanner;
use firewall::brain_client::BrainClient;

pub struct WafProxy {
    pub scanner: Arc<Mutex<Scanner>>,
    pub brain: Arc<BrainClient>, 
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool, Box<Error>> {
        let mut scanner = self.scanner.lock().await;

        // --- LAYER 0: NORMALIZATION ---
        let raw_uri = session.req_header().uri.to_string();
        let clean_uri = RequestNormalizer::normalize(&raw_uri);
        
        // --- LAYER 1: FAST SCAN (URI) ---
        if let Some(rule_id) = scanner.matches(&clean_uri) {
            println!("[BLOCK] Layer 1 URI | Rule ID: {} | Payload: {}", rule_id, clean_uri);
            session.respond_error(403).await?;
            return Ok(true);
        }

        // --- LAYER 1: FAST SCAN (Headers) ---
        if let Some(ua) = session.get_header("User-Agent") {
            let clean_ua = RequestNormalizer::normalize(&ua.to_str().unwrap_or_default());
            if let Some(rule_id) = scanner.matches(&clean_ua) {
                println!("[BLOCK] Layer 1 Header | Rule ID: {} | Payload: {}", rule_id, clean_ua);
                session.respond_error(403).await?;
                return Ok(true);
            }
        }

        // Drop the lock before the network call to the Brain
        drop(scanner);

        // --- LAYER 2: TRANSFORMER BRAIN ---
        if self.brain.analyze(&clean_uri).await {
            println!("[BLOCK] Layer 2 BRAIN | Flagged URI: {}", clean_uri);
            session.respond_error(403).await?;
            return Ok(true);
        }

        println!("[PASS] All layers cleared URI: {}", clean_uri);
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        if let Some(chunk) = body {
            let clean_body = RequestNormalizer::normalize(&String::from_utf8_lossy(chunk));
            
            // Layer 1 Check on body chunk
            {
                let mut scanner = self.scanner.lock().await;
                if let Some(rule_id) = scanner.matches(&clean_body) {
                    println!("[BLOCK] Layer 1 Body | Rule ID: {} | Payload: {}", rule_id, clean_body);
                    // In Pingora 0.7, we use Error::new(HTTPStatus(403))
                    return Err(Error::new(HTTPStatus(403)));
                }
            }

            // Layer 2 Body Check (Small chunks only)
            if clean_body.len() < 1000 && self.brain.analyze(&clean_body).await {
                 println!("[BLOCK] Layer 2 BRAIN Body | Flagged Content: {}", clean_body);
                 return Err(Error::new(HTTPStatus(403)));
            }
        }
        Ok(())
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>, Box<Error>> {
        // Pointing to a public DNS for testing
        let peer = Box::new(HttpPeer::new("1.1.1.1:443", true, "one.one.one.one".to_string()));
        Ok(peer)
    }
}

fn main() {
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let brain_api_url = "http://127.0.0.1:5000/analyze";

    let waf_proxy = WafProxy {
        scanner: Arc::new(Mutex::new(Scanner::new("rules.yaml"))),
        brain: Arc::new(BrainClient::new(brain_api_url)),
    };

    let mut proxy_service = http_proxy_service(&server.configuration, waf_proxy);
    proxy_service.add_tcp("0.0.0.0:8000"); 

    println!("--------------------------------------------------");
    println!("🚀 Production WAF is live on http://localhost:8000");
    println!("🛡️  Layer 1: Normalization + Hyperscan Active");
    println!("🧠  Layer 2: Transformer Brain Bridge Active");
    println!("--------------------------------------------------");

    server.add_service(proxy_service);
    server.run_forever();
}