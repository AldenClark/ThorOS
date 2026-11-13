use crate::config::Config;
use crate::probe::{epoch_ms, Observation};
use crate::router::{self, Router};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;

pub fn local_clock() -> String {
    Command::new("date").arg("+%Y-%m-%d %H:%M:%S%z").output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| epoch_ms().to_string())
}

pub fn filename_clock() -> String {
    let stamp = local_clock();
    let result: String = stamp.chars().filter(|c| c.is_ascii_digit()).take(14).collect();
    if result.len() == 14 { result } else { epoch_ms().to_string() }
}

fn csv(s: &str) -> String {
    if s.contains(',') || s.contains('\n') || s.contains('"') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else { s.into() }
}

fn observation_line(o: &Observation) -> String {
    format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        o.epoch_ms, csv(&o.kind), csv(&o.target), csv(&o.mode), u8::from(o.ok),
        o.elapsed_ms, optional_number(o.dns_ms), optional_number(o.tcp_ms),
        optional_number(o.tls_ms), optional_number(o.ttfb_ms), csv(&o.http),
        csv(&o.ip), o.bytes, format!("{:.0}", o.speed_bps), csv(&o.detail))
}

fn optional_number(v: Option<f64>) -> String {
    v.map(|n| format!("{n:.2}")).unwrap_or_default()
}

#[derive(Default)]
struct Stats {
    count: usize,
    failures: usize,
    slow: usize,
    durations: Vec<u64>,
}

impl Stats {
    fn observe(&mut self, o: &Observation) {
        self.count += 1;
        if !o.ok { self.failures += 1; }
        else {
            self.durations.push(o.elapsed_ms);
            if o.elapsed_ms >= 3000 { self.slow += 1; }
        }
    }
    fn percentile(&self, p: usize) -> u64 {
        if self.durations.is_empty() { return 0; }
        let mut sorted = self.durations.clone();
        sorted.sort_unstable();
        let i = ((sorted.len() - 1) * p + 99) / 100;
        sorted[i.min(sorted.len() - 1)]
    }
}

#[derive(Clone, Default)]
struct RouterCounters {
    cpu_total: u64,
    cpu_idle: u64,
    softnet_dropped: u64,
    softnet_squeezed: u64,
    fe_installs: i64,
    fe_deletes: i64,
    fe_rejected: i64,
    fe_flows: i64,
    fe_enabled: i64,
    fe_error: i64,
    dma_busy: i64,
    dma_invalid: i64,
    qm_no_buffer: i64,
    qm_drop: i64,
    qm_tail_drop: i64,
    qm_l3te_packets: i64,
    conntrack: i64,
    conntrack_max: i64,
}

fn section_line<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let marker = format!("[{name}]\n");
    s.split_once(&marker)?.1.lines().next()
}

fn router_counters(s: &str) -> RouterCounters {
    let mut c = RouterCounters {
        fe_installs: router::field(s, "fe", "installs").unwrap_or(-1),
        fe_deletes: router::field(s, "fe", "deletes").unwrap_or(-1),
        fe_rejected: router::field(s, "fe", "rejected").unwrap_or(-1),
        fe_flows: router::field(s, "fe", "flows").unwrap_or(-1),
        fe_enabled: router::field(s, "fe", "enabled").unwrap_or(-1),
        fe_error: router::field(s, "fe", "error").unwrap_or(-1),
        dma_busy: router::field(s, "dma_state", "busy").unwrap_or(-1),
        dma_invalid: router::field(s, "dma_state", "invalid").unwrap_or(-1),
        qm_no_buffer: router::field(s, "qm_state", "no_buffer").unwrap_or(-1),
        qm_drop: router::field(s, "qm_state", "fe_drop").unwrap_or(-1),
        qm_tail_drop: router::field(s, "qm_state", "l3te_tail_drop").unwrap_or(-1),
        qm_l3te_packets: router::field(s, "qm_state", "l3te_packets").unwrap_or(-1),
        conntrack: section_line(s, "conntrack").and_then(|x| x.parse().ok()).unwrap_or(-1),
        conntrack_max: section_line(s, "conntrack_max").and_then(|x| x.parse().ok()).unwrap_or(-1),
        ..Default::default()
    };
    if let Some(cpu) = section_line(s, "cpu") {
        let v: Vec<u64> = cpu.split_whitespace().skip(1).take(8)
            .filter_map(|x| x.parse().ok()).collect();
        if v.len() >= 5 { c.cpu_total = v.iter().sum(); c.cpu_idle = v[3] + v[4]; }
    }
    if let Some((_, tail)) = s.split_once("[softnet]\n") {
        for line in tail.lines().take_while(|line| !line.starts_with('[')) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 3 {
                c.softnet_dropped += u64::from_str_radix(fields[1], 16).unwrap_or(0);
                c.softnet_squeezed += u64::from_str_radix(fields[2], 16).unwrap_or(0);
            }
        }
    }
    c
}

struct ActiveIncident {
    until_ms: u128,
    stream: BufWriter<File>,
}

#[derive(Clone)]
struct IncidentSummary {
    at_ms: u128,
    cause: String,
    file: String,
}

pub struct Reporter {
    dir: PathBuf,
    started_ms: u128,
    started_local: String,
    samples: BufWriter<File>,
    router_samples: BufWriter<File>,
    router_metrics: BufWriter<File>,
    stats: BTreeMap<String, Stats>,
    recent: VecDeque<Observation>,
    recent_router: String,
    previous_router: Option<RouterCounters>,
    last_router: Option<RouterCounters>,
    cpu_percent: Option<f64>,
    dropped_delta: u64,
    squeezed_delta: u64,
    recent_tcp: VecDeque<(u128, bool)>,
    recent_gateway: VecDeque<(u128, bool)>,
    recent_dns: VecDeque<(u128, String, bool)>,
    recent_http: VecDeque<(u128, String, bool, u64)>,
    active: Option<ActiveIncident>,
    incidents: Vec<IncidentSummary>,
    snapshot_handles: Vec<thread::JoinHandle<()>>,
    last_trigger_ms: u128,
    ssh_failures: usize,
}

impl Reporter {
    pub fn new(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut samples = BufWriter::new(File::create(dir.join("probes.csv"))?);
        writeln!(samples, "epoch_ms,kind,target,mode,ok,elapsed_ms,dns_ms,tcp_ms,tls_ms,ttfb_ms,http_code,remote_ip,bytes,speed_Bps,detail")?;
        let mut metrics = BufWriter::new(File::create(dir.join("router-metrics.csv"))?);
        writeln!(metrics, "epoch_ms,cpu_percent,softnet_drop_total,softnet_drop_delta,softnet_squeeze_total,softnet_squeeze_delta,conntrack,conntrack_max,fe_enabled,fe_error,fe_flows,fe_installs,fe_deletes,fe_rejected,dma_busy,dma_invalid,qm_no_buffer,qm_fe_drop,qm_tail_drop,qm_l3te_packets")?;
        let started_ms = epoch_ms();
        Ok(Self {
            dir: dir.to_owned(), started_ms, started_local: local_clock(),
            samples, router_samples: BufWriter::new(File::create(dir.join("router.log"))?),
            router_metrics: metrics, stats: BTreeMap::new(), recent: VecDeque::new(),
            recent_router: String::new(), previous_router: None, last_router: None,
            cpu_percent: None, dropped_delta: 0, squeezed_delta: 0,
            recent_tcp: VecDeque::new(), recent_gateway: VecDeque::new(),
            recent_dns: VecDeque::new(), recent_http: VecDeque::new(),
            active: None, incidents: Vec::new(), snapshot_handles: Vec::new(),
            last_trigger_ms: 0, ssh_failures: 0,
        })
    }

    pub fn dir(&self) -> &Path { &self.dir }
    pub fn probe_count(&self) -> usize { self.stats.values().map(|s| s.count).sum() }
    pub fn incident_count(&self) -> usize { self.incidents.len() }

    pub fn add_probe(&mut self, o: Observation, router: Option<Arc<Router>>) -> io::Result<()> {
        let at = o.epoch_ms;
        let line = observation_line(&o);
        writeln!(self.samples, "{line}")?;
        self.samples.flush()?;
        self.stats.entry(format!("{} / {}", o.kind, o.mode)).or_default().observe(&o);
        self.recent.push_back(o.clone());
        while self.recent.front().is_some_and(|p| at.saturating_sub(p.epoch_ms) > 180_000) {
            self.recent.pop_front();
        }
        if let Some(incident) = self.active.as_mut() {
            writeln!(incident.stream, "{line}")?;
            incident.stream.flush()?;
            if at >= incident.until_ms {
                self.active = None;
            }
        }
        self.track_health(&o);
        if let Some(reason) = self.incident_reason(at) {
            self.trigger(at, reason, router)?;
        }
        Ok(())
    }

    fn track_health(&mut self, o: &Observation) {
        match o.kind.as_str() {
            "tcp" => self.recent_tcp.push_back((o.epoch_ms, o.ok)),
            "gateway" => self.recent_gateway.push_back((o.epoch_ms, o.ok)),
            "dns" => self.recent_dns.push_back((o.epoch_ms, o.mode.clone(), o.ok)),
            "http" => self.recent_http.push_back((o.epoch_ms, o.target.clone(), o.ok, o.elapsed_ms)),
            _ => (),
        }
        self.recent_tcp.retain(|(t, _)| o.epoch_ms.saturating_sub(*t) <= 30_000);
        self.recent_gateway.retain(|(t, _)| o.epoch_ms.saturating_sub(*t) <= 30_000);
        self.recent_dns.retain(|(t, _, _)| o.epoch_ms.saturating_sub(*t) <= 35_000);
        self.recent_http.retain(|(t, _, _, _)| o.epoch_ms.saturating_sub(*t) <= 35_000);
    }

    fn incident_reason(&self, now: u128) -> Option<&'static str> {
        if now.saturating_sub(self.last_trigger_ms) < 45_000 || self.active.is_some() {
            return None;
        }
        let last_tcp: Vec<_> = self.recent_tcp.iter().filter(|(at, _)| now.saturating_sub(*at) <= 12_000).collect();
        if last_tcp.len() >= 2 && last_tcp.iter().rev().take(2).all(|(_, ok)| !ok) {
            return Some("two consecutive pinned IPv4 TCP:443 failures (WAN new connections)");
        }
        let last_gateway: Vec<_> = self.recent_gateway.iter().filter(|(at, _)| now.saturating_sub(*at) <= 12_000).collect();
        if last_gateway.len() >= 2 && last_gateway.iter().rev().take(2).all(|(_, ok)| !ok) {
            return Some("two consecutive LAN gateway ICMP failures");
        }
        let last_http: Vec<_> = self.recent_http.iter().filter(|(at, _, _, _)| now.saturating_sub(*at) <= 25_000).collect();
        let bad_hosts: std::collections::BTreeSet<_> = last_http.iter().filter(|(_, _, ok, _)| !ok).map(|(_, host, _, _)| host.as_str()).collect();
        if bad_hosts.len() >= 3 {
            return Some("HTTP failures across three distinct mainland sites");
        }
        let slow_hosts: std::collections::BTreeSet<_> = last_http.iter().filter(|(_, _, ok, ms)| *ok && *ms >= 4000).map(|(_, host, _, _)| host.as_str()).collect();
        if slow_hosts.len() >= 2 {
            return Some("HTTP latency >= 4 seconds on two distinct sites");
        }
        let router_dns: Vec<_> = self.recent_dns.iter()
            .filter(|(at, server, _)| now.saturating_sub(*at) <= 35_000 && server != "223.5.5.5")
            .collect();
        if router_dns.len() >= 2 && router_dns.iter().rev().take(2).all(|(_, _, ok)| !ok) {
            return Some("two consecutive router DNS A-query failures");
        }
        None
    }

    fn trigger(&mut self, at: u128, reason: &str, router: Option<Arc<Router>>) -> io::Result<()> {
        self.last_trigger_ms = at;
        let id = self.incidents.len() + 1;
        let file = format!("incident-{id:03}-{at}.txt");
        let mut stream = BufWriter::new(File::create(self.dir.join(&file))?);
        writeln!(stream, "INCIDENT #{id} | {} | unix_ms={at}", local_clock())?;
        writeln!(stream, "Reason: {reason}")?;
        writeln!(stream, "Signals are detection heuristics; NOT established root cause.")?;
        writeln!(stream, "--- Previous 180 seconds: epoch_ms,kind,target,mode,ok,elapsed_ms,dns_ms,tcp_ms,tls_ms,ttfb_ms,http_code,remote_ip,bytes,speed_Bps,detail")?;
        for o in &self.recent { writeln!(stream, "{}", observation_line(o))?; }
        writeln!(stream, "--- Latest router read-only sample ---\n{}", self.recent_router)?;
        writeln!(stream, "--- Following 60 seconds ---")?;
        stream.flush()?;
        self.active = Some(ActiveIncident { until_ms: at + 60_000, stream });
        self.incidents.push(IncidentSummary { at_ms: at, cause: reason.into(), file: file.clone() });
        eprintln!("[INCIDENT] {}: {reason} -> {}", local_clock(), self.dir.join(&file).display());

        let out_dir = self.dir.clone();
        let handle = thread::spawn(move || {
            let local = router::local_snapshot();
            let _ = fs::write(out_dir.join(format!("incident-{id:03}-macos.txt")), local);
            if let Some(ssh) = router {
                let remote = ssh.incident_snapshot();
                let _ = fs::write(out_dir.join(format!("incident-{id:03}-router.txt")), remote);
            }
        });
        self.snapshot_handles.push(handle);
        self.summary()?;
        Ok(())
    }

    pub fn add_router(&mut self, at: u128, text: String) -> io::Result<()> {
        writeln!(self.router_samples, "\n=== router unix_ms={at} ===\n{text}")?;
        self.router_samples.flush()?;
        if text.contains("[ssh_failure]") {
            self.ssh_failures += 1;
            eprintln!("[SSH] router sample failed at {at}: {}", text.lines().next().unwrap_or(""));
            return Ok(());
        }
        let c = router_counters(&text);
        if let Some(prev) = &self.previous_router {
            let delta_total = c.cpu_total.saturating_sub(prev.cpu_total);
            let delta_idle = c.cpu_idle.saturating_sub(prev.cpu_idle);
            if delta_total > 0 {
                self.cpu_percent = Some(100.0 * (delta_total.saturating_sub(delta_idle) as f64) / delta_total as f64);
            }
            self.dropped_delta = c.softnet_dropped.saturating_sub(prev.softnet_dropped);
            self.squeezed_delta = c.softnet_squeezed.saturating_sub(prev.softnet_squeezed);
        }
        writeln!(self.router_metrics, "{at},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.cpu_percent.map(|x| format!("{x:.2}")).unwrap_or_default(),
            c.softnet_dropped, self.dropped_delta, c.softnet_squeezed, self.squeezed_delta,
            c.conntrack, c.conntrack_max, c.fe_enabled, c.fe_error,
            c.fe_flows, c.fe_installs, c.fe_deletes, c.fe_rejected,
            c.dma_busy, c.dma_invalid, c.qm_no_buffer, c.qm_drop,
            c.qm_tail_drop, c.qm_l3te_packets)?;
        self.router_metrics.flush()?;
        self.previous_router = Some(c.clone());
        self.last_router = Some(c);
        self.recent_router = text;
        Ok(())
    }

    pub fn summary(&mut self) -> io::Result<()> {
        let path = self.dir.join("summary.md");
        let tmp = self.dir.join("summary.md.tmp");
        let mut f = BufWriter::new(File::create(&tmp)?);
        writeln!(f, "# TYFZA1 WAN diagnostic summary\n")?;
        writeln!(f, "- Started: {} (unix_ms={})", self.started_local, self.started_ms)?;
        writeln!(f, "- Last report: {} (unix_ms={})", local_clock(), epoch_ms())?;
        writeln!(f, "- Samples: {}; incidents: {}; router SSH failures: {}\n",
            self.probe_count(), self.incident_count(), self.ssh_failures)?;
        writeln!(f, "The monitor never changes router state. HTTP 4xx/5xx responses still prove TCP/TLS reachability; curl transport errors do not.\n")?;
        writeln!(f, "## Probe latency\n")?;
        writeln!(f, "| Probe/mode | Samples | Transport errors | Slow >=3s | p50 (ms) | p95 (ms) | p99 (ms) |")?;
        writeln!(f, "|---|---:|---:|---:|---:|---:|---:|")?;
        for (name, s) in &self.stats {
            writeln!(f, "| {} | {} | {} | {} | {} | {} | {} |",
                name.replace('|', "\\|"), s.count, s.failures, s.slow,
                s.percentile(50), s.percentile(95), s.percentile(99))?;
        }
        writeln!(f, "\n## Latest router state\n")?;
        if let Some(c) = &self.last_router {
            writeln!(f, "- CPU usage over previous sampling interval: {:.1}%", self.cpu_percent.unwrap_or(0.0))?;
            writeln!(f, "- softnet dropped/time_squeeze increase: {} / {}", self.dropped_delta, self.squeezed_delta)?;
            writeln!(f, "- conntrack: {} / {}", c.conntrack, c.conntrack_max)?;
            writeln!(f, "- FE: enabled={} error={} flows={} installs={} deletes={} rejected={}",
                c.fe_enabled, c.fe_error, c.fe_flows, c.fe_installs, c.fe_deletes, c.fe_rejected)?;
            writeln!(f, "- DMA: busy={} invalid={}; QM: no_buffer={} fe_drop={} tail_drop={} L3TE_packets={}",
                c.dma_busy, c.dma_invalid, c.qm_no_buffer, c.qm_drop, c.qm_tail_drop, c.qm_l3te_packets)?;
        } else { writeln!(f, "No router samples yet.")?; }
        writeln!(f, "\n## Detected incidents\n")?;
        if self.incidents.is_empty() { writeln!(f, "None yet.")?; }
        else {
            writeln!(f, "| Unix ms | Trigger | Evidence |")?;
            writeln!(f, "|---:|---|---|")?;
            for e in &self.incidents {
                writeln!(f, "| {} | {} | {} |", e.at_ms, e.cause, e.file)?;
            }
        }
        writeln!(f, "\n## Artifacts\n")?;
        writeln!(f, "- `probes.csv`: timestamps, sites, curl DNS/connect/TLS/TTFB, errors and timing; all direct connections (no proxy).")?;
        writeln!(f, "- `router-metrics.csv`: FE/conntrack/CPU/softnet/DMA/QM counters, for time correlation.")?;
        writeln!(f, "- `router.log`: full raw read-only periodic samples.")?;
        writeln!(f, "- `incident-*.txt`: up to 180 seconds preceding and 60 seconds following a trigger.")?;
        writeln!(f, "- `incident-*-router.txt` and `incident-*-macos.txt`: independent extended snapshots.")?;
        writeln!(f, "\nInterpretation: FE `rejected` can include unsupported flows, not necessarily failure. TCP `connect` only tests handshake, not full TLS. Bandwidth measured via netdev counters may exclude hardware-offloaded traffic. A false positive from a specific website does not prove WAN outage.\n")?;
        writeln!(f, "Logs may contain public IP addresses, device MAC addresses, hostnames, and process data. Redact before public sharing.")?;
        f.flush()?;
        drop(f);
        fs::rename(tmp, path)
    }

    pub fn finish(&mut self) -> io::Result<()> {
        for handle in self.snapshot_handles.drain(..) {
            let _ = handle.join();
        }
        self.samples.flush()?;
        self.router_metrics.flush()?;
        self.router_samples.flush()?;
        if let Some(active) = &mut self.active { active.stream.flush()?; }
        self.summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn router_metric_parsing() {
        let s = "[cpu]\ncpu 1 2 3 4 5 6 7 8 0\n[softnet]\n00000001 00000002 00000003\n[conntrack]\n420\n[conntrack_max]\n16384\n[fe]\navailable=1 enabled=1 error=0 flows=23 installs=44 deletes=21 rejected=2\n[qm_state]\nfe_drop=0 no_buffer=0 l3te_tail_drop=0 l3te_packets=310\n";
        let m = router_counters(s);
        assert_eq!(m.conntrack, 420);
        assert_eq!(m.fe_flows, 23);
        assert_eq!(m.softnet_dropped, 2);
        assert_eq!(m.softnet_squeezed, 3);
        assert_eq!(m.cpu_total, 36);
    }
    #[test]
    fn csv_escaping() {
        assert_eq!(csv("ok"), "ok");
        assert_eq!(csv("a,\"b\""), "\"a,\"\"b\"\"\"\"\"");
    }
}

