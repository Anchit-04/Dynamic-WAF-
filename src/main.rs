use async_trait::async_trait;
use pingora::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use bytes::Bytes;

mod firewall;
use firewall::normalize::RequestNormalizer;
use firewall::scanner::Scanner;
use firewall::brain_client::BrainClient;

const MAX_BODY_SIZE: usize = 10 * 1024;

struct ProxyConfig {
    upstream_host: String,
    upstream_port: u16,
    upstream_tls: bool,
    upstream_sni: String,
    listen_addr: String,
    brain_url: String,
    rules_path: String,
}

impl ProxyConfig {
    fn from_env() -> Self {
        ProxyConfig {
            upstream_host: std::env::var("UPSTREAM_HOST").unwrap_or_else(|_| "1.1.1.1".into()),
            upstream_port: std::env::var("UPSTREAM_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(443),
            upstream_tls: std::env::var("UPSTREAM_TLS")
                .ok()
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
            upstream_sni: std::env::var("UPSTREAM_SNI").unwrap_or_else(|_| "one.one.one.one".into()),
            listen_addr: std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".into()),
            brain_url: std::env::var("BRAIN_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:5000/analyze".into()),
            rules_path: std::env::var("RULES_PATH").unwrap_or_else(|_| "rules.yaml".into()),
        }
    }
}

pub struct WafContext {
    request_body: String,
}

pub struct WafProxy {
    pub scanner: Arc<Mutex<Scanner>>,
    pub brain: Arc<BrainClient>,
    config: ProxyConfig,
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = WafContext;

    fn new_ctx(&self) -> WafContext {
        WafContext {
            request_body: String::new(),
        }
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut WafContext) -> Result<bool, Box<Error>> {
        let scanner = self.scanner.lock().await;

        let raw_uri = session.req_header().uri.to_string();
        let clean_uri = RequestNormalizer::normalize(&raw_uri);

        if let Some(rule_id) = scanner.matches(&clean_uri) {
            println!("[BLOCK] Layer 1 URI | Rule ID: {} | Payload: {}", rule_id, clean_uri);
            session.respond_error(403).await?;
            return Ok(true);
        }

        if let Some(ua) = session.get_header("User-Agent") {
            let clean_ua = RequestNormalizer::normalize(&ua.to_str().unwrap_or_default());
            if let Some(rule_id) = scanner.matches(&clean_ua) {
                println!("[BLOCK] Layer 1 Header | Rule ID: {} | Payload: {}", rule_id, clean_ua);
                session.respond_error(403).await?;
                return Ok(true);
            }
        }

        drop(scanner);

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
        end_of_stream: bool,
        ctx: &mut WafContext,
    ) -> Result<(), Box<Error>> {
        if let Some(chunk) = body {
            let chunk_str = String::from_utf8_lossy(chunk);

            // Layer 1 fast regex scan on each body chunk
            let scanner = self.scanner.lock().await;
            let clean_chunk = RequestNormalizer::normalize(&chunk_str);
            if let Some(rule_id) = scanner.matches(&clean_chunk) {
                println!("[BLOCK] Layer 1 Body | Rule ID: {} | Payload: {}", rule_id, clean_chunk);
                return Err(Error::new(HTTPStatus(403)));
            }
            drop(scanner);

            // Accumulate full body for Layer 2 (bounded to prevent OOM)
            if ctx.request_body.len() < MAX_BODY_SIZE {
                ctx.request_body.push_str(&chunk_str);
            }
        }

        // Layer 2 brain analysis on the complete body
        if end_of_stream && !ctx.request_body.is_empty() {
            let clean_body = RequestNormalizer::normalize(&ctx.request_body);
            if self.brain.analyze(&clean_body).await {
                println!("[BLOCK] Layer 2 BRAIN Body | Flagged Content: {}", clean_body);
                return Err(Error::new(HTTPStatus(403)));
            }
        }

        Ok(())
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut WafContext) -> Result<Box<HttpPeer>, Box<Error>> {
        let addr = format!("{}:{}", self.config.upstream_host, self.config.upstream_port);
        let peer = Box::new(HttpPeer::new(&addr, self.config.upstream_tls, self.config.upstream_sni.clone()));
        Ok(peer)
    }
}

fn main() {
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let config = ProxyConfig::from_env();

    let listen_addr = config.listen_addr.clone();

    let waf_proxy = WafProxy {
        scanner: Arc::new(Mutex::new(Scanner::new(&config.rules_path))),
        brain: Arc::new(BrainClient::new(&config.brain_url)),
        config,
    };

    let mut proxy_service = http_proxy_service(&server.configuration, waf_proxy);
    proxy_service.add_tcp(&listen_addr);

    println!("--------------------------------------------------");
    println!("  Production WAF is live on http://{}", listen_addr);
    println!("  Layer 1: Normalization + Regex Active");
    println!("  Layer 2: Transformer Brain Bridge Active");
    println!("--------------------------------------------------");

    server.add_service(proxy_service);
    server.run_forever();
}