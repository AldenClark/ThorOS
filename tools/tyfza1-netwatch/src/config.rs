use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub router: String,
    pub user: String,
    pub port: u16,
    pub output: PathBuf,
    pub duration_minutes: u64,
    pub sites: Vec<String>,
    pub probe_host: String,
    pub probe_ip: Option<Ipv4Addr>,
    pub no_ssh: bool,
    pub http_interval: u64,
    pub tcp_interval: u64,
    pub dns_interval: u64,
    pub gateway_interval: u64,
    pub router_interval: u64,
    pub load_url: Option<String>,
    pub load_rate_kib: u32,
    pub load_streams: u8,
    pub load_seconds: u64,
    pub load_every_minutes: u64,
}

const DEFAULT_SITES: &[&str] = &[
    "https://www.baidu.com/",
    "https://www.qq.com/",
    "https://www.163.com/",
    "https://www.jd.com/",
    "https://www.bilibili.com/",
    "https://www.aliyun.com/",
    "https://www.sina.com.cn/",
];

pub fn usage() -> &'static str {
    "TYFZA1 Netwatch — long-running macOS/WAN diagnostic monitor (read-only router SSH)\n\
     Usage: tyfza1-netwatch [options]\n\
       --router IP               Router/LAN gateway (default 192.168.1.1)\n\
       --user USER               Router SSH user (default root)\n\
       --ssh-port PORT           SSH port (default 22)\n\
       --out DIR                 Results directory (default results/TIMESTAMP)\n\
       --duration-min MIN        Stop after MIN minutes; 0 = until Ctrl+C (default 0)\n\
       --sites FILE              HTTPS URL list, one per line\n\
       --probe-host HOST         Pinned IPv4 TCP:443 probe hostname (default www.baidu.com)\n\
       --probe-ip IPV4           Pin an explicit reachable IPv4 server instead of DNS lookup\n\
       --http-every SEC          Rotate a site every SEC (default 3)\n\
       --tcp-every SEC           Pinned-IP TCP connect interval (default 2)\n\
       --dns-every SEC           DNS probe interval (default 10)\n\
       --gateway-every SEC       Gateway ICMP probe interval (default 3)\n\
       --router-every SEC        Router read-only SSH samples (default 5)\n\
       --no-ssh                  Skip SSH and router telemetry (client-only mode)\n\
       --load-url HTTPS_URL      Opt-in capped download stress, OFF by default\n\
       --load-rate-kib KIBPS     Per-stream speed cap (default 512 KiB/s)\n\
       --load-streams N          Concurrent capped download streams, 1..8 (default 2)\n\
       --load-seconds SEC        Maximum stress-window duration (default 20)\n\
       --load-every-min MIN      Stress interval in minutes (default 20)\n\
       -h, --help               Show this help\n\
     NOTES: Tests use direct connections (--noproxy '*'). HTTP 403/405 is\n\
     counted as transport success. SSH asks for authentication once via\n\
     OpenSSH ControlMaster, then reuses the local session.\n"
}

impl Config {
    pub fn parse() -> Result<Option<Self>, String> {
        Self::parse_args(env::args().skip(1))
    }

    fn parse_args<I: Iterator<Item = String>>(mut args: I) -> Result<Option<Self>, String> {
        let mut cfg = Self {
            router: "192.168.1.1".into(),
            user: "root".into(),
            port: 22,
            output: PathBuf::new(),
            duration_minutes: 0,
            sites: DEFAULT_SITES.iter().map(|s| s.to_string()).collect(),
            probe_host: "www.baidu.com".into(),
            probe_ip: None,
            no_ssh: false,
            http_interval: 3,
            tcp_interval: 2,
            dns_interval: 10,
            gateway_interval: 3,
            router_interval: 5,
            load_url: None,
            load_rate_kib: 512,
            load_streams: 2,
            load_seconds: 20,
            load_every_minutes: 20,
        };
        while let Some(arg) = args.next() {
            if arg == "-h" || arg == "--help" {
                return Ok(None);
            }
            if arg == "--no-ssh" {
                cfg.no_ssh = true;
                continue;
            }
            let v = args.next().ok_or_else(|| format!("Missing value for {arg}"))?;
            match arg.as_str() {
                "--router" => cfg.router = v,
                "--user" => cfg.user = v,
                "--ssh-port" => cfg.port = parse_num(&v, &arg)?,
                "--out" => cfg.output = PathBuf::from(v),
                "--duration-min" => cfg.duration_minutes = parse_num(&v, &arg)?,
                "--sites" => {
                    let source = fs::read_to_string(&v)
                        .map_err(|e| format!("Cannot read sites file {v}: {e}"))?;
                    cfg.sites = source
                        .lines()
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && !s.starts_with('#'))
                        .map(str::to_owned)
                        .collect();
                }
                "--probe-host" => cfg.probe_host = v,
                "--probe-ip" => {
                    cfg.probe_ip = Some(v.parse().map_err(|_| "--probe-ip expects IPv4".to_owned())?)
                }
                "--http-every" => cfg.http_interval = parse_num(&v, &arg)?,
                "--tcp-every" => cfg.tcp_interval = parse_num(&v, &arg)?,
                "--dns-every" => cfg.dns_interval = parse_num(&v, &arg)?,
                "--gateway-every" => cfg.gateway_interval = parse_num(&v, &arg)?,
                "--router-every" => cfg.router_interval = parse_num(&v, &arg)?,
                "--load-url" => cfg.load_url = Some(v),
                "--load-rate-kib" => cfg.load_rate_kib = parse_num(&v, &arg)?,
                "--load-streams" => cfg.load_streams = parse_num(&v, &arg)?,
                "--load-seconds" => cfg.load_seconds = parse_num(&v, &arg)?,
                "--load-every-min" => cfg.load_every_minutes = parse_num(&v, &arg)?,
                _ => return Err(format!("Unknown option: {arg}")),
            }
        }

        if cfg.port == 0 || cfg.load_streams == 0 || cfg.load_streams > 8 {
            return Err("SSH port must be nonzero and load streams must be 1..8".into());
        }
        if cfg.sites.is_empty() || cfg.sites.iter().any(|s| !safe_https_url(s)) {
            return Err("Sites must be non-empty HTTPS URLs without whitespace".into());
        }
        if cfg.load_url.as_ref().is_some_and(|url| !safe_https_url(url)) {
            return Err("--load-url must be HTTPS without whitespace".into());
        }
        if cfg.load_rate_kib == 0 || cfg.load_rate_kib > 25_600 {
            return Err("--load-rate-kib must be 1..25600 (25 MiB/s/stream max)".into());
        }
        if cfg.load_seconds == 0 || cfg.load_seconds > 90 || cfg.load_every_minutes == 0 {
            return Err("Load duration must be 1..90 seconds; load interval must be nonzero".into());
        }
        for n in [cfg.http_interval, cfg.tcp_interval, cfg.dns_interval,
            cfg.gateway_interval, cfg.router_interval]
        {
            if n == 0 || n > 3600 {
                return Err("Probe intervals must be 1..3600 seconds".into());
            }
        }
        if cfg.router.is_empty() || cfg.router.starts_with('-')
            || !cfg.router.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            || cfg.user.is_empty() || cfg.user.starts_with('-')
            || !cfg.user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            || cfg.probe_host.is_empty()
            || !cfg.probe_host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err("Router, SSH user, and probe host contain invalid characters".into());
        }
        Ok(Some(cfg))
    }
}

fn parse_num<T: std::str::FromStr>(v: &str, flag: &str) -> Result<T, String> {
    v.parse().map_err(|_| format!("Invalid number for {flag}: {v}"))
}

fn safe_https_url(url: &str) -> bool {
    url.starts_with("https://") && !url.chars().any(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_safe_defaults() {
        let c = Config::parse_args(std::iter::empty()).unwrap().unwrap();
        assert_eq!(c.router, "192.168.1.1");
        assert_eq!(c.sites.len(), 7);
        assert!(c.load_url.is_none());
    }
    #[test]
    fn reject_wrong_scheme_and_load_caps() {
        assert!(Config::parse_args(vec!["--load-url", "http://unsafe.example/"]
            .into_iter().map(str::to_owned)).is_err());
        assert!(Config::parse_args(vec!["--load-streams", "9"]
            .into_iter().map(str::to_owned)).is_err());
    }
}

