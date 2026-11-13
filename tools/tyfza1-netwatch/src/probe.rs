use crate::config::Config;
use crate::process;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct Observation {
    pub epoch_ms: u128,
    pub kind: String,
    pub target: String,
    pub mode: String,
    pub ok: bool,
    pub elapsed_ms: u64,
    pub dns_ms: Option<f64>,
    pub tcp_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: Option<f64>,
    pub http: String,
    pub ip: String,
    pub bytes: u64,
    pub speed_bps: f64,
    pub detail: String,
}

#[derive(Debug)]
pub enum Event {
    Probe(Observation),
    RouterSample { at: u128, text: String },
}

pub fn epoch_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

fn new_obs(kind: &str, target: impl Into<String>, mode: &str) -> Observation {
    Observation {
        epoch_ms: epoch_ms(), kind: kind.into(), target: target.into(), mode: mode.into(),
        ok: false, elapsed_ms: 0, dns_ms: None, tcp_ms: None,
        tls_ms: None, ttfb_ms: None, http: String::new(), ip: String::new(),
        bytes: 0, speed_bps: 0.0, detail: String::new(),
    }
}

pub fn resolve_pinned_ip(host: &str) -> Result<Ipv4Addr, String> {
    let resolved = (host, 443).to_socket_addrs()
        .map_err(|e| format!("Cannot resolve pinned TCP probe host {host}: {e}"))?;
    let ips: Vec<_> = resolved.filter_map(|a| match a { SocketAddr::V4(v) => Some(*v.ip()), _ => None })
        .collect();
    for ip in &ips {
        if TcpStream::connect_timeout(&SocketAddr::new((*ip).into(), 443), Duration::from_secs(2)).is_ok() {
            return Ok(*ip);
        }
    }
    Err(format!("No reachable IPv4 TCP:443 address for {host}; pass --probe-ip or retry on a healthy network"))
}

pub fn tcp(ip: Ipv4Addr) -> Observation {
    let mut o = new_obs("tcp", ip.to_string(), "pinned-ipv4:443");
    let start = Instant::now();
    let addr = SocketAddr::new(ip.into(), 443);
    match TcpStream::connect_timeout(&addr, Duration::from_millis(1800)) {
        Ok(stream) => {
            o.ok = true;
            drop(stream);
        }
        Err(e) => o.detail = e.to_string(),
    }
    o.elapsed_ms = start.elapsed().as_millis() as u64;
    o.epoch_ms = epoch_ms();
    o
}

pub fn gateway_ping(router: &str) -> Observation {
    let mut o = new_obs("gateway", router, "icmp");
    let args = vec!["-n".into(), "-c".into(), "1".into(), router.into()];
    match process::run("ping", &args, None, Duration::from_millis(2500)) {
        Ok(r) => { o.ok = r.success(); o.elapsed_ms = r.elapsed.as_millis() as u64;
            if !o.ok { o.detail = r.error_summary(); } },
        Err(e) => o.detail = e.to_string(),
    }
    o.epoch_ms = epoch_ms();
    o
}

fn parse_curl_metrics(o: &mut Observation, stdout: &str) {
    // Fields are tab-delimited and contain no user-supplied delimiters.
    let fields: Vec<_> = stdout.trim().split('\t').collect();
    if fields.len() < 9 {
        o.detail = format!("curl did not return 9 metrics: {}", stdout.trim());
        return;
    }
    o.http = fields[0].into();
    o.ip = fields[1].into();
    o.dns_ms = fields[2].parse::<f64>().ok().map(|v| v * 1000.0);
    o.tcp_ms = fields[3].parse::<f64>().ok().map(|v| v * 1000.0);
    o.tls_ms = fields[4].parse::<f64>().ok().map(|v| v * 1000.0);
    o.ttfb_ms = fields[5].parse::<f64>().ok().map(|v| v * 1000.0);
    o.elapsed_ms = fields[6].parse::<f64>().unwrap_or(0.0).mul_add(1000.0, 0.0).round() as u64;
    o.bytes = fields[7].parse::<f64>().unwrap_or(0.0) as u64;
    o.speed_bps = fields[8].parse::<f64>().unwrap_or(0.0);
}

fn curl_args(url: &str, head: bool, family: &str, timeout_secs: u64) -> Vec<String> {
    let mut args = vec![
        "--silent".into(), "--show-error".into(),
        "--noproxy".into(), "*".into(),
        "--location".into(), "--max-redirs".into(), "3".into(),
        "--connect-timeout".into(), "3".into(),
        "--max-time".into(), timeout_secs.to_string(),
        "--output".into(), "/dev/null".into(),
        "--write-out".into(),
        "%{http_code}\t%{remote_ip}\t%{time_namelookup}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}\t%{size_download}\t%{speed_download}".into(),
    ];
    if family == "ipv4" { args.push("-4".into()); }
    if head { args.push("--head".into()); }
    args.push(url.into());
    args
}

pub fn http(url: &str, family: &str) -> Observation {
    let mut o = new_obs("http", url, family);
    let args = curl_args(url, true, family, 9);
    match process::run("curl", &args, None, Duration::from_secs(11)) {
        Ok(r) => {
            parse_curl_metrics(&mut o, &r.stdout);
            if o.elapsed_ms == 0 { o.elapsed_ms = r.elapsed.as_millis() as u64; }
            o.ok = r.success() && o.http != "000" && !o.http.is_empty();
            if !o.ok { o.detail = format!("curl {}: {}", r.code.unwrap_or(-1), r.error_summary()); }
        }
        Err(e) => o.detail = e.to_string(),
    }
    o.epoch_ms = epoch_ms();
    o
}

pub fn dns(domain: &str, server: &str) -> Observation {
    let mut o = new_obs("dns", domain, server);
    let args = vec![
        format!("@{server}"), "+short".into(), "+tries=1".into(),
        "+time=2".into(), "A".into(), domain.into(),
    ];
    match process::run("dig", &args, None, Duration::from_secs(4)) {
        Ok(r) => {
            o.elapsed_ms = r.elapsed.as_millis() as u64;
            let ips: Vec<_> = r.stdout.split_whitespace().filter_map(|s| s.parse::<Ipv4Addr>().ok()).collect();
            o.ok = r.success() && !ips.is_empty();
            o.ip = ips.first().map(ToString::to_string).unwrap_or_default();
            if !o.ok { o.detail = format!("{}; {}", r.error_summary(), r.stdout.trim()); }
        }
        Err(e) => o.detail = e.to_string(),
    }
    o.epoch_ms = epoch_ms();
    o
}

pub fn load(url: &str, kib_per_sec: u32, seconds: u64, index: u8) -> Observation {
    let mut o = new_obs("load", url, format!("stream-{index},cap-{kib_per_sec}KiBps").as_str());
    let mut args = curl_args(url, false, "ipv4", seconds);
    let insert_at = args.len() - 1;
    args.insert(insert_at, "--limit-rate".into());
    args.insert(insert_at + 1, format!("{kib_per_sec}k"));
    let timeout = Duration::from_secs(seconds + 3);
    match process::run("curl", &args, None, timeout) {
        Ok(r) => {
            parse_curl_metrics(&mut o, &r.stdout);
            if o.elapsed_ms == 0 { o.elapsed_ms = r.elapsed.as_millis() as u64; }
            // Exit 28 at exactly the requested test window is normal if bytes arrived.
            o.ok = (r.success() || r.code == Some(28)) && o.bytes > 0;
            if !o.ok { o.detail = format!("curl {}: {}", r.code.unwrap_or(-1), r.error_summary()); }
            else if r.code == Some(28) { o.detail = "expected duration cap".into(); }
        }
        Err(e) => o.detail = e.to_string(),
    }
    o.epoch_ms = epoch_ms();
    o
}

fn wait(stop: &AtomicBool, seconds: u64) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn spawn_workers(cfg: &Config, pinned: Option<Ipv4Addr>, tx: Sender<Event>, stop: Arc<AtomicBool>) {
    if let Some(ip) = pinned {
        let t = tx.clone(); let flag = stop.clone(); let every = cfg.tcp_interval;
        thread::spawn(move || while !flag.load(Ordering::Relaxed) {
            if t.send(Event::Probe(tcp(ip))).is_err() { break; }
            wait(&flag, every);
        });
    }
    {
        let t = tx.clone(); let flag = stop.clone(); let sites = cfg.sites.clone();
        let every = cfg.http_interval;
        thread::spawn(move || {
            let mut n = 0usize;
            while !flag.load(Ordering::Relaxed) {
                let site = &sites[n % sites.len()];
                // Alternates system dual-stack behavior vs forced IPv4.
                let family = if n % 2 == 0 { "auto" } else { "ipv4" };
                if t.send(Event::Probe(http(site, family))).is_err() { break; }
                n += 1;
                wait(&flag, every);
            }
        });
    }
    {
        let t = tx.clone(); let flag = stop.clone(); let every = cfg.dns_interval;
        let router = cfg.router.clone(); let domain = cfg.probe_host.clone();
        thread::spawn(move || {
            let mut n = 0;
            while !flag.load(Ordering::Relaxed) {
                let server = if n % 2 == 0 { router.as_str() } else { "223.5.5.5" };
                if t.send(Event::Probe(dns(&domain, server))).is_err() { break; }
                n += 1;
                wait(&flag, every);
            }
        });
    }
    {
        let t = tx.clone(); let flag = stop.clone(); let every = cfg.gateway_interval;
        let router = cfg.router.clone();
        thread::spawn(move || while !flag.load(Ordering::Relaxed) {
            if t.send(Event::Probe(gateway_ping(&router))).is_err() { break; }
            wait(&flag, every);
        });
    }
    if let Some(url) = cfg.load_url.clone() {
        let flag = stop.clone(); let interval = cfg.load_every_minutes * 60;
        let streams = cfg.load_streams; let cap = cfg.load_rate_kib; let window = cfg.load_seconds;
        thread::spawn(move || {
            // Wait 60 seconds for a clean baseline before controlled load starts.
            wait(&flag, 60);
            while !flag.load(Ordering::Relaxed) {
                let mut handles = Vec::new();
                for i in 0..streams {
                    let url = url.clone();
                    let t = tx.clone();
                    handles.push(thread::spawn(move || {
                        let _ = t.send(Event::Probe(load(&url, cap, window, i + 1)));
                    }));
                }
                for h in handles { let _ = h.join(); }
                wait(&flag, interval);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn curl_metrics() {
        let mut o = new_obs("http", "example.com", "auto");
        parse_curl_metrics(&mut o, "403\t1.2.3.4\t0.01\t0.02\t0.03\t0.04\t0.05\t0\t0");
        assert_eq!(o.http, "403");
        assert_eq!(o.ip, "1.2.3.4");
        assert_eq!(o.elapsed_ms, 50);
    }
}

