use async_trait::async_trait;
use log::{info, warn};
use pingora::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use bytes::Bytes;

mod firewall;
use firewall::brain_client::BrainClient;
use firewall::normalize::RequestNormalizer;
use firewall::ratelimit::RateLimiter;
use firewall::scanner::Scanner;

const MAX_BODY_SIZE: usize = 10 * 1024;

struct ProxyConfig {
    upstream_host: String,
    upstream_port: u16,
    upstream_tls: bool,
    upstream_sni: String,
    listen_addr: String,
    brain_url: String,
    rules_path: String,
    rate_limit_requests: usize,
    rate_limit_window: u64,
    allowlist_paths: Vec<String>,
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
            rate_limit_requests: std::env::var("RATE_LIMIT_REQUESTS")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(100),
            rate_limit_window: std::env::var("RATE_LIMIT_WINDOW")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(60),
            allowlist_paths: std::env::var("ALLOWLIST_PATHS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }
}

pub struct WafContext {
    request_body: String,
}

pub struct WafProxy {
    pub scanner: Arc<Mutex<Scanner>>,
    pub brain: Arc<BrainClient>,
    pub rate_limiter: RateLimiter,
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
        let client_ip = session
            .get_header("X-Forwarded-For")
            .and_then(|v| v.to_str().ok().map(|s| s.to_string()))
            .unwrap_or_else(|| {
                session
                    .client_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default()
            });

        if !self.rate_limiter.check(&client_ip) {
            warn!("rate_limit ip={}", client_ip);
            session.respond_error(429).await?;
            return Ok(true);
        }

        let scanner = self.scanner.lock().await;
        let raw_uri = session.req_header().uri.to_string();
        let clean_uri = RequestNormalizer::normalize(&raw_uri);

        if let Some(rule_id) = scanner.matches(&clean_uri) {
            info!("block layer=1 type=uri rule={} ip={} payload={}", rule_id, client_ip, clean_uri);
            session.respond_error(403).await?;
            return Ok(true);
        }

        if let Some(ua) = session.get_header("User-Agent") {
            let clean_ua = RequestNormalizer::normalize(&ua.to_str().unwrap_or_default());
            if let Some(rule_id) = scanner.matches(&clean_ua) {
                info!("block layer=1 type=header rule={} ip={} payload={}", rule_id, client_ip, clean_ua);
                session.respond_error(403).await?;
                return Ok(true);
            }
        }

        drop(scanner);

        let allowlisted = self.config.allowlist_paths.iter().any(|p| raw_uri.starts_with(p));
        if !allowlisted && self.brain.analyze(&clean_uri).await {
            info!("block layer=2 type=uri ip={} payload={}", client_ip, clean_uri);
            session.respond_error(403).await?;
            return Ok(true);
        }

        let status = if allowlisted { "pass_allowlisted" } else { "pass" };
        info!("{} uri={} ip={}", status, clean_uri, client_ip);
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

            let scanner = self.scanner.lock().await;
            let clean_chunk = RequestNormalizer::normalize(&chunk_str);
            if let Some(rule_id) = scanner.matches(&clean_chunk) {
                info!("block layer=1 type=body rule={} payload={}", rule_id, clean_chunk);
                return Err(Error::new(HTTPStatus(403)));
            }
            drop(scanner);

            if ctx.request_body.len() < MAX_BODY_SIZE {
                ctx.request_body.push_str(&chunk_str);
            }
        }

        if end_of_stream && !ctx.request_body.is_empty() {
            let clean_body = RequestNormalizer::normalize(&ctx.request_body);
            if self.brain.analyze(&clean_body).await {
                info!("block layer=2 type=body payload={}", clean_body);
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let config = ProxyConfig::from_env();
    let listen_addr = config.listen_addr.clone();

    let upstream_host = config.upstream_host.clone();
    let upstream_port = config.upstream_port;
    let upstream_tls = config.upstream_tls;

    let waf_proxy = WafProxy {
        scanner: Arc::new(Mutex::new(Scanner::new(&config.rules_path))),
        brain: Arc::new(BrainClient::new(&config.brain_url)),
        rate_limiter: RateLimiter::new(config.rate_limit_requests, config.rate_limit_window),
        config,
    };

    let mut proxy_service = http_proxy_service(&server.configuration, waf_proxy);
    proxy_service.add_tcp(&listen_addr);

    info!("started listen={} upstream={}:{} tls={}", listen_addr, upstream_host, upstream_port, upstream_tls);

    server.add_service(proxy_service);
    server.run_forever();
}