use crate::config::GuardConfig;
use std::path::Path;

use super::{write_config, TranslateError};

/// Generate suricata.yaml and update.yaml from the [network] config.
pub fn generate(config: &GuardConfig, run_dir: &Path) -> Result<(), TranslateError> {
    let net = &config.network;
    let suricata_dir = run_dir.join("suricata");
    std::fs::create_dir_all(&suricata_dir)?;

    let yaml = build_suricata_yaml(config);
    write_config(&suricata_dir, "suricata.yaml", &yaml)?;

    let update_yaml = build_update_yaml(net);
    write_config(&suricata_dir, "update.yaml", &update_yaml)?;

    Ok(())
}

fn build_suricata_yaml(config: &GuardConfig) -> String {
    let net = &config.network;

    let is_ips = net.mode == "ips";

    // Build interface list for af-packet
    let interfaces: String = net
        .interfaces
        .iter()
        .map(|iface| {
            format!(
                "    - interface: {iface}\n      cluster-id: 99\n      cluster-type: cluster_flow\n      defrag: yes{}",
                if is_ips { "\n      copy-mode: ips\n      copy-iface: default" } else { "" }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let af_packet = if net.interfaces.is_empty() {
        "af-packet:\n    - interface: default\n      cluster-id: 99".to_string()
    } else {
        format!("af-packet:\n{interfaces}")
    };

    // Log directory inside our run dir
    let log_dir = config
        .guard
        .run_dir
        .join("suricata")
        .join("log")
        .display()
        .to_string();

    format!(
        r#"%YAML 1.1
---

vars:
  address-groups:
    HOME_NET: "[{home_net}]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"

default-log-dir: {log_dir}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            tagged-packets: yes
        - dns
        - tls
        - http
        - flow
        - stats:
            totals: yes
            threads: no

{af_packet}

app-layer:
  protocols:
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes
    tls:
      enabled: yes
    http:
      enabled: yes

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
"#,
        home_net = net.home_net,
        log_dir = log_dir,
        af_packet = af_packet,
    )
}

fn build_update_yaml(net: &crate::config::NetworkSection) -> String {
    let sources: String = net
        .rulesets
        .iter()
        .map(|rs| {
            match rs.as_str() {
                "emerging-threats" => "  - et/open".to_string(),
                "abuse-ch" => "  - abuse-ch/urlhaus".to_string(),
                other => format!("  - {other}"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"# suricata-update configuration
enable-sources:
{sources}

# Reload suricata after update
reload-command: suricatasc -c reload-rules
"#,
        sources = sources,
    )
}
