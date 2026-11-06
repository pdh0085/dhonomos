//! Hub firewall: `table inet dhonomos_wg`, replaced as a whole via `nft -f -`.
//! Forward only within 1 interface -> members of a network reach each other + its sites,
//! never another network or other host interfaces.
//! Hub host itself: only ping on its tunnel addresses + replies to own traffic
//! (e.g. own ping to a member). No other table touched.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::plan::Desired;

/// Table name as `nft` uses it.
pub(crate) const TABLE: &str = "inet dhonomos_wg";

/// Firewall interfaces: (name, hub address), by port.
pub(crate) fn interfaces(desired: &Desired) -> Vec<(String, Ipv4Addr)> {
    desired
        .interfaces
        .iter()
        .map(|i| (i.name.clone(), i.address))
        .collect()
}

/// Table definition, same form as `nft list table` output.
pub(crate) fn render_table(interfaces: &[(String, Ipv4Addr)]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "table {TABLE} {{");
    s.push_str("\tchain forward {\n");
    s.push_str("\t\ttype filter hook forward priority filter; policy accept;\n");
    for (name, _) in interfaces {
        let _ = writeln!(s, "\t\tiifname \"{name}\" oifname \"{name}\" accept");
    }
    s.push_str("\t\tiifname \"dwg*\" drop\n");
    s.push_str("\t\toifname \"dwg*\" drop\n");
    s.push_str("\t}\n");
    s.push_str("\tchain input {\n");
    s.push_str("\t\ttype filter hook input priority filter; policy accept;\n");
    s.push_str("\t\tiifname \"dwg*\" ct state established,related accept\n");
    for (name, address) in interfaces {
        let _ = writeln!(
            s,
            "\t\tiifname \"{name}\" ip daddr {address} icmp type echo-request accept"
        );
    }
    s.push_str("\t\tiifname \"dwg*\" drop\n");
    s.push_str("\t}\n");
    s.push_str("}\n");
    s
}

/// Input of `nft -f -`: ensure table, delete, define again -> 1 transaction.
pub(crate) fn render_script(interfaces: &[(String, Ipv4Addr)]) -> String {
    format!(
        "table {TABLE}\ndelete table {TABLE}\n{}",
        render_table(interfaces)
    )
}

/// Lines trimmed, empty ones dropped.
fn normalized(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// `nft list table` output = [`render_table`] output, line by line.
pub(crate) fn same_table(listed: &str, rendered: &str) -> bool {
    normalized(listed) == normalized(rendered)
}

/// Run `nft -f -` with `script`. Error has nft's message.
pub(crate) async fn apply(nft: &Path, script: &str) -> Result<(), String> {
    let mut child = Command::new(nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("running {}: {e}", nft.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .await
            .map_err(|e| format!("writing to {}: {e}", nft.display()))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("running {}: {e}", nft.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} -f - failed ({}): {}",
            nft.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Table as `nft list table` prints it. List fails (no table) -> `None`. Read only.
pub(crate) async fn list(nft: &Path) -> Result<Option<String>, String> {
    let out = Command::new(nft)
        .args(["list", "table", "inet", "dhonomos_wg"])
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("running {}: {e}", nft.display()))?;
    Ok(out
        .status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_networks() {
        let interfaces = [
            ("dwg51820".to_owned(), Ipv4Addr::new(10, 77, 0, 1)),
            ("dwg51821".to_owned(), Ipv4Addr::new(10, 77, 1, 1)),
        ];
        assert_eq!(
            render_script(&interfaces),
            "table inet dhonomos_wg
delete table inet dhonomos_wg
table inet dhonomos_wg {
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname \"dwg51820\" oifname \"dwg51820\" accept
\t\tiifname \"dwg51821\" oifname \"dwg51821\" accept
\t\tiifname \"dwg*\" drop
\t\toifname \"dwg*\" drop
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname \"dwg*\" ct state established,related accept
\t\tiifname \"dwg51820\" ip daddr 10.77.0.1 icmp type echo-request accept
\t\tiifname \"dwg51821\" ip daddr 10.77.1.1 icmp type echo-request accept
\t\tiifname \"dwg*\" drop
\t}
}
"
        );
    }

    #[test]
    fn no_networks() {
        assert_eq!(
            render_script(&[]),
            "table inet dhonomos_wg
delete table inet dhonomos_wg
table inet dhonomos_wg {
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname \"dwg*\" drop
\t\toifname \"dwg*\" drop
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname \"dwg*\" ct state established,related accept
\t\tiifname \"dwg*\" drop
\t}
}
"
        );
    }

    #[test]
    fn listings_compare_by_lines() {
        let rendered = render_table(&[("dwg51820".to_owned(), Ipv4Addr::new(10, 77, 0, 1))]);
        let listed = rendered.replace('\t', "        ") + "\n";
        assert!(same_table(&listed, &rendered));
        let other = render_table(&[("dwg51821".to_owned(), Ipv4Addr::new(10, 77, 0, 1))]);
        assert!(!same_table(&other, &rendered));
        assert!(!same_table("", &rendered));
    }
}
