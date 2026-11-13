use crate::config::Config;
use crate::process;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Only reads of procfs/sysfs and diagnostic commands. Never use `echo >`, uci set,
// service restarts, firewall reloads, ethtool changes, or any writes on the router.
const FAST_SCRIPT: &str = r#"
printf '[clock]\n'; date '+%Y-%m-%d %H:%M:%S%z'; cat /proc/uptime
printf '[load]\n'; cat /proc/loadavg
printf '[cpu]\n'; head -n 6 /proc/stat
printf '[softnet]\n'; cat /proc/net/softnet_stat
printf '[conntrack]\n'; cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null
printf '[conntrack_max]\n'; cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null
printf '[fe]\n'; cat /sys/bus/platform/devices/4f5500000.pon/fe 2>&1
printf '[pon_state]\n'; cat /sys/bus/platform/devices/4f5500000.pon/state 2>&1
printf '[pon_optical]\n'; cat /sys/bus/platform/devices/4f5500000.pon/optical 2>&1
printf '[pon_activation]\n'; cat /sys/bus/platform/devices/4f5500000.pon/activation 2>&1
printf '[dma_state]\n'; cat /sys/bus/platform/devices/4f4300000.ethernet/dma_state 2>&1
printf '[qm_state]\n'; cat /sys/bus/platform/devices/4f4300000.ethernet/qm_state 2>&1
printf '[qm_voqs]\n'; cat /sys/bus/platform/devices/4f4300000.ethernet/qm_voqs 2>&1
printf '[idle_poll_ms]\n'; cat /sys/bus/platform/devices/4f4300000.ethernet/idle_poll_ms 2>&1
printf '[netdev_counters]\n'
for d in pppoe-wan pon0 pon0.41 br-lan lan1 lan2 lan3 lan4; do
  p="/sys/class/net/$d/statistics"
  if [ -d "$p" ]; then
    printf 'dev=%s ' "$d"
    for x in rx_bytes tx_bytes rx_packets tx_packets rx_dropped tx_dropped rx_errors tx_errors; do
      v=$(cat "$p/$x" 2>/dev/null); printf '%s=%s ' "$x" "$v"
    done
    printf '\n'
  fi
done
printf '[interrupts]\n'; cat /proc/interrupts
"#;

const FULL_SCRIPT: &str = r#"
printf '[router_clock]\n'; date '+%Y-%m-%d %H:%M:%S%z'
printf '[wan_status]\n'; ubus call network.interface.wan status 2>&1
printf '[wan6_status]\n'; ubus call network.interface.wan6 status 2>&1
printf '[ip_links]\n'; ip -s link show 2>&1
printf '[ip_routes4]\n'; ip -4 route show table all 2>&1
printf '[ip_routes6]\n'; ip -6 route show table all 2>&1
printf '[ip_neighbors]\n'; ip neigh show 2>&1
printf '[memory]\n'; cat /proc/meminfo
printf '[snmp]\n'; cat /proc/net/snmp
printf '[netstat]\n'; cat /proc/net/netstat
printf '[nf_conntrack_stat]\n'; cat /proc/net/stat/nf_conntrack 2>&1
printf '[nf_conntrack_entries]\n'; if [ -r /proc/net/nf_conntrack ]; then head -n 1000 /proc/net/nf_conntrack; else printf 'not available\n'; fi
printf '[softirqs]\n'; cat /proc/softirqs
printf '[firewall_rules]\n'; nft -a list ruleset 2>&1 | tail -n 220
printf '[processes]\n'; ps w 2>&1
printf '[recent_logread]\n'; logread -l 250 2>&1
printf '[recent_dmesg]\n'; dmesg | tail -n 200
"#;

pub struct Router {
    destination: String,
    port: u16,
    control: PathBuf,
    temp_dir: PathBuf,
}

impl Router {
    pub fn connect(cfg: &Config) -> io::Result<Arc<Self>> {
        // /tmp is deliberately used to keep AF_UNIX socket paths under macOS's limit.
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let temp_dir = PathBuf::from(format!("/tmp/tyfza1-watch-{}-{stamp}", std::process::id()));
        fs::create_dir(&temp_dir)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o700))?;
        }
        let router = Arc::new(Self {
            destination: format!("{}@{}", cfg.user, cfg.router),
            port: cfg.port,
            control: temp_dir.join("ssh.sock"),
            temp_dir,
        });
        eprintln!("Establishing one SSH master session to {} (may ask for password/host key)...", router.destination);
        let status = Command::new("ssh")
            .args(["-f", "-N", "-M", "-S"])
            .arg(&router.control)
            .args(["-p", &router.port.to_string()])
            .args([
                "-o", "ControlMaster=yes",
                "-o", "ControlPersist=120",
                "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=2",
                "-o", "ForwardAgent=no",
                "-o", "ClearAllForwardings=yes",
                "-o", "StrictHostKeyChecking=ask",
            ])
            .arg(&router.destination)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!("SSH master failed: {status}")));
        }
        let check = router.exec("printf 'router-ssh-ready\\n'", Duration::from_secs(6))?;
        if !check.success() || !check.stdout.contains("router-ssh-ready") {
            return Err(io::Error::other(format!("SSH connected but commands failed: {}", check.error_summary())));
        }
        Ok(router)
    }

    fn exec(&self, script: &str, timeout: Duration) -> io::Result<process::CommandResult> {
        let args = vec![
            "-T".into(), "-S".into(), self.control.to_string_lossy().into_owned(),
            "-p".into(), self.port.to_string(),
            "-o".into(), "ControlMaster=auto".into(),
            "-o".into(), "BatchMode=yes".into(),
            "-o".into(), "ConnectTimeout=5".into(),
            "-o".into(), "ForwardAgent=no".into(),
            "--".into(), self.destination.clone(), "sh".into(), "-s".into(),
        ];
        process::run("ssh", &args, Some(script.as_bytes()), timeout)
    }

    pub fn sample(&self) -> String {
        match self.exec(FAST_SCRIPT, Duration::from_secs(8)) {
            Ok(result) if result.success() => result.stdout,
            Ok(result) => format!("[ssh_failure] {}\n{}\n", result.error_summary(), result.stdout),
            Err(err) => format!("[ssh_failure] spawn error: {err}\n"),
        }
    }

    pub fn incident_snapshot(&self) -> String {
        let mut text = self.sample();
        text.push_str("\n[extended_snapshot]\n");
        match self.exec(FULL_SCRIPT, Duration::from_secs(20)) {
            Ok(result) => {
                text.push_str(&result.stdout);
                if !result.success() {
                    text.push_str(&format!("\n[extended_snapshot_error] {}\n", result.error_summary()));
                }
            }
            Err(err) => text.push_str(&format!("\n[extended_snapshot_error] {err}\n")),
        }
        text
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        // Stops only the SSH master owned by this tool, never anything on the router.
        let _ = Command::new("ssh")
            .arg("-S").arg(&self.control)
            .arg("-O").arg("exit")
            .arg("-p").arg(self.port.to_string())
            .arg(&self.destination)
            .output();
        let _ = fs::remove_file(&self.control);
        let _ = fs::remove_dir(&self.temp_dir);
    }
}

pub fn local_snapshot() -> String {
    let commands: [(&str, &[&str]); 4] = [
        ("route", &["-n", "get", "default"]),
        ("netstat", &["-rn", "-f", "inet"]),
        ("scutil", &["--dns"]),
        ("ifconfig", &[]),
    ];
    let mut out = String::new();
    for (cmd, args) in commands {
        out.push_str(&format!("\n[macos_{cmd}]\n"));
        let a: Vec<String> = args.iter().map(|x| x.to_string()).collect();
        match process::run(cmd, &a, None, Duration::from_secs(5)) {
            Ok(r) => { out.push_str(&r.stdout); if !r.success() { out.push_str(&r.error_summary()); } },
            Err(e) => out.push_str(&e.to_string()),
        }
    }
    out
}

/// Extracts a named field from one [section] only, avoiding similarly named counters.
pub fn field(text: &str, section: &str, key: &str) -> Option<i64> {
    let tag = format!("[{section}]");
    let (_, after) = text.split_once(&tag)?;
    let data = after.split_once('\n')?.1;
    let section_text = data.split("\n[").next().unwrap_or(data);
    section_text
        .split_whitespace()
        .filter_map(|entry| entry.split_once('='))
        .find_map(|(k, v)| (k == key).then(|| v.parse::<i64>().ok()).flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_fe_and_qm_without_cross_section_confusion() {
        let text = "[fe]\navailable=1 enabled=1 error=0 flows=312 installs=500 deletes=188 rejected=2\n[qm_state]\nno_buffer=0 fe_drop=0\n";
        assert_eq!(field(text, "fe", "flows"), Some(312));
        assert_eq!(field(text, "qm_state", "fe_drop"), Some(0));
        assert_eq!(field(text, "qm_state", "flows"), None);
    }
}

