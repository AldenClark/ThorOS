mod config;
mod probe;
mod process;
mod report;
mod router;

use config::Config;
use probe::{epoch_ms, Event};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
mod unix_signals {
    use super::{Ordering, SIGNAL_STOP};

    extern "C" fn signal_handler(_: i32) {
        SIGNAL_STOP.store(true, Ordering::Relaxed);
    }

    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }

    pub fn install() {
        // SIGINT=2 (Ctrl+C), SIGTERM=15. Handler only touches a lock-free atomic.
        unsafe {
            signal(2, signal_handler as usize);
            signal(15, signal_handler as usize);
        }
    }
}

fn requirements() -> Result<(), String> {
    for program in ["curl", "dig", "ping", "ssh"] {
        let ok = std::process::Command::new("/usr/bin/which")
            .arg(program).output().map(|r| r.status.success()).unwrap_or(false);
        if !ok { return Err(format!("macOS command not found: {program}")); }
    }
    Ok(())
}

fn run(mut cfg: Config) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    eprintln!("WARNING: this tool is optimized for macOS; local network commands may differ on this OS.");

    requirements()?;
    if cfg.output.as_os_str().is_empty() {
        cfg.output = PathBuf::from("results").join(report::filename_clock());
    }
    let mut reporter = report::Reporter::new(&cfg.output)
        .map_err(|e| format!("Create report directory: {e}"))?;
    let router = if cfg.no_ssh { None } else {
        Some(router::Router::connect(&cfg)
            .map_err(|e| format!("Router SSH setup failed: {e}\nHint: verify 'ssh -p {} {}@{}' works from Terminal. Password is requested only once, then reused through SSH ControlMaster. Or use --no-ssh for a client-only test.", cfg.port, cfg.user, cfg.router))?)
    };

    let pinned = match cfg.probe_ip {
        Some(ip) => Some(ip),
        None => match probe::resolve_pinned_ip(&cfg.probe_host) {
            Ok(ip) => Some(ip),
            Err(err) => { eprintln!("[WARN] {err}. Direct TCP test is disabled, other tests continue."); None }
        }
    };
    println!("TYFZA1 Netwatch 0.1.0 | {}", report::local_clock());
    println!("Router: {}@{}:{} | SSH: {}", cfg.user, cfg.router, cfg.port, if cfg.no_ssh { "disabled" } else { "read-only" });
    println!("Pinned direct TCP: {}", pinned.map(|p| format!("{p}:443")).unwrap_or_else(|| "disabled".into()));
    println!("Sites: {}; controlled load: {}", cfg.sites.len(),
        if let Some(ref url) = cfg.load_url { format!("ON ({} streams * {} KiB/s, {}s, every {}min; {url})", cfg.load_streams, cfg.load_rate_kib, cfg.load_seconds, cfg.load_every_minutes) }
        else { "OFF (default, low network impact)".into() });
    println!("Report: {}\nPress Ctrl+C to stop and finalize.\n", reporter.dir().display());

    #[cfg(unix)]
    unix_signals::install();
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Event>();
    probe::spawn_workers(&cfg, pinned, tx.clone(), stop.clone());

    if let Some(ref ssh) = router {
        let ssh = ssh.clone();
        let flag = stop.clone();
        let t = tx.clone();
        let interval = cfg.router_interval;
        thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                let at = epoch_ms();
                let snapshot = ssh.sample();
                if t.send(Event::RouterSample { at, text: snapshot }).is_err() { break; }
                let until = Instant::now() + Duration::from_secs(interval);
                while Instant::now() < until && !flag.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }
    drop(tx); // Remaining senders belong to workers.

    let since = Instant::now();
    let mut latest_report = Instant::now();
    while !SIGNAL_STOP.load(Ordering::Relaxed)
        && (cfg.duration_minutes == 0 || since.elapsed() < Duration::from_secs(cfg.duration_minutes.saturating_mul(60)))
    {
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(Event::Probe(o)) => {
                reporter.add_probe(o, router.clone()).map_err(|e| format!("Writing probe evidence: {e}"))?;
            }
            Ok(Event::RouterSample { at, text }) => {
                reporter.add_router(at, text).map_err(|e| format!("Writing router evidence: {e}"))?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if latest_report.elapsed() >= Duration::from_secs(30) {
            reporter.summary().map_err(|e| format!("Updating summary: {e}"))?;
            println!("[{}] probes={} incidents={} elapsed={}s",
                report::local_clock(), reporter.probe_count(), reporter.incident_count(), since.elapsed().as_secs());
            latest_report = Instant::now();
        }
    }
    stop.store(true, Ordering::Relaxed);
    println!("Finishing evidence snapshots and report...");
    reporter.finish().map_err(|e| format!("Finalizing: {e}"))?;
    println!("Done. Open {}/summary.md", reporter.dir().display());
    Ok(())
}

fn main() {
    match Config::parse() {
        Ok(None) => print!("{}", config::usage()),
        Ok(Some(cfg)) => {
            if let Err(e) = run(cfg) {
                eprintln!("ERROR: {e}\n");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("ERROR: {e}\n\n{}", config::usage());
            std::process::exit(2);
        }
    }
}

