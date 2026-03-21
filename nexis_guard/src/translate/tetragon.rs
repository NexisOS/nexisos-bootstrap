use crate::config::GuardConfig;
use serde_json::{json, Value};
use std::path::Path;

use super::{write_config, TranslateError};

/// Generate Tetragon TracingPolicy JSON files from the [processes] config.
pub fn generate(config: &GuardConfig, run_dir: &Path) -> Result<(), TranslateError> {
    let proc = &config.processes;
    let tetragon_dir = run_dir.join("tetragon");
    std::fs::create_dir_all(&tetragon_dir)?;

    // Policy: alert on sensitive file reads
    if !proc.monitor_sensitive_files.is_empty() {
        let policy = sensitive_file_policy(proc);
        let json = serde_json::to_string_pretty(&policy)?;
        write_config(&tetragon_dir, "sensitive-files.json", &json)?;
    }

    // Policy: detect shell spawned from service
    if proc.alert_on_shell_from_service {
        let policy = shell_from_service_policy(proc);
        let json = serde_json::to_string_pretty(&policy)?;
        write_config(&tetragon_dir, "shell-from-service.json", &json)?;
    }

    // Policy: privilege escalation detection
    if proc.alert_on_privilege_escalation {
        let policy = privilege_escalation_policy();
        let json = serde_json::to_string_pretty(&policy)?;
        write_config(&tetragon_dir, "privilege-escalation.json", &json)?;
    }

    // Policy: kernel module load detection
    if proc.alert_on_kernel_module_load {
        let policy = kernel_module_policy();
        let json = serde_json::to_string_pretty(&policy)?;
        write_config(&tetragon_dir, "kernel-module-load.json", &json)?;
    }

    Ok(())
}

/// TracingPolicy that fires on open() of sensitive files.
fn sensitive_file_policy(proc: &crate::config::ProcessesSection) -> Value {
    let paths: Vec<&str> = proc
        .monitor_sensitive_files
        .iter()
        .filter_map(|p| p.to_str())
        .collect();

    json!({
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": "nexis-guard-sensitive-files"
        },
        "spec": {
            "kprobes": [{
                "call": "fd_install",
                "syscall": false,
                "args": [{
                    "index": 0,
                    "type": "int"
                }, {
                    "index": 1,
                    "type": "file"
                }],
                "selectors": [{
                    "matchArgs": [{
                        "index": 1,
                        "operator": "Prefix",
                        "values": paths
                    }],
                    "matchActions": [{
                        "action": "Post"
                    }]
                }]
            }]
        }
    })
}

/// TracingPolicy that detects interactive shells spawned by service processes.
fn shell_from_service_policy(proc: &crate::config::ProcessesSection) -> Value {
    let shells: Vec<&str> = proc
        .shell_binaries
        .iter()
        .map(|s| s.as_str())
        .collect();

    json!({
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": "nexis-guard-shell-from-service"
        },
        "spec": {
            "tracepoints": [{
                "subsystem": "syscalls",
                "event": "sys_enter_execve",
                "args": [{
                    "index": 4,
                    "type": "string"
                }],
                "selectors": [{
                    "matchArgs": [{
                        "index": 4,
                        "operator": "In",
                        "values": shells
                    }],
                    "matchActions": [{
                        "action": "Post"
                    }]
                }]
            }]
        }
    })
}

/// TracingPolicy that watches for setuid/setgid transitions.
fn privilege_escalation_policy() -> Value {
    json!({
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": "nexis-guard-privilege-escalation"
        },
        "spec": {
            "kprobes": [{
                "call": "__sys_setuid",
                "syscall": false,
                "args": [{
                    "index": 0,
                    "type": "int"
                }],
                "selectors": [{
                    "matchArgs": [{
                        "index": 0,
                        "operator": "Equal",
                        "values": ["0"]
                    }],
                    "matchActions": [{
                        "action": "Post"
                    }]
                }]
            }]
        }
    })
}

/// TracingPolicy that watches for kernel module loading.
fn kernel_module_policy() -> Value {
    json!({
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": "nexis-guard-kernel-module-load"
        },
        "spec": {
            "kprobes": [{
                "call": "finit_module",
                "syscall": false,
                "args": [{
                    "index": 0,
                    "type": "int"
                }, {
                    "index": 1,
                    "type": "string"
                }, {
                    "index": 2,
                    "type": "int"
                }],
                "selectors": [{
                    "matchActions": [{
                        "action": "Post"
                    }]
                }]
            }]
        }
    })
}
