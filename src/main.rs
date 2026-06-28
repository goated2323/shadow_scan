use regex::Regex;
use std::fs::{self, File};
use std::io::{self, BufRead, Write, Cursor};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::process::{Command, exit};
use std::env;
use rayon::prelude::*;

struct ScanConfig {
    quiet: bool,
    verbose: bool,
}

fn format_json_output(file_name: &str, line_number: usize, alert_type: &str, target: &str, masked_value: &str) -> String {
    format!(
        "    {{\n      \"file\": \"{}\",\n      \"line\": {},\n      \"type\": \"{}\",\n      \"target\": \"{}\",\n      \"masked_value\": \"{}\"\n    }}",
        file_name, line_number, alert_type, target, masked_value
    )
}

fn calculate_shannon_entropy(text: &str) -> f64 {
    if text.is_empty() { return 0.0; }
    let mut frequencies = HashMap::new();
    for c in text.chars() {
        *frequencies.entry(c).or_insert(0) += 1;
    }
    let len = text.chars().count() as f64;
    let mut entropy = 0.0;
    for &count in frequencies.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn analyze_stream<R: BufRead>(
    reader: R, 
    file_ident: &str, 
    re_secrets: &Regex, 
    re_ssh: &Regex, 
    specific_patterns: &[(Regex, &str, &str)],
    report_list: &Arc<Mutex<Vec<String>>>,
    config: &ScanConfig
) -> io::Result<usize> {
    let mut alert_count = 0;
    let mut local_alerts = Vec::new();

    let whitelist = vec!["self.", "systemctl", "sev_un", "deta", "null", "fail", "max_"];
    let context_indicators = vec!["=", ":", "secret", "key", "password", "token", "env", "set", "export"];

    for (index, line) in reader.lines().enumerate() {
        if let Ok(line) = line {
            if line.contains('\0') { return Ok(alert_count); }

            if re_ssh.is_match(&line) {
                alert_count += 1;
                if !config.quiet {
                    println!("[CRITICAL] {}:{} - Private key detected", file_ident, index + 1);
                }
                local_alerts.push(format_json_output(file_ident, index + 1, "PrivateKey", "SSH/RSA", "-----BEGIN..."));
                continue;
            }

            let mut matched_specific = false;
            for (re, name, alert_type) in specific_patterns {
                if let Some(caps) = re.captures(&line) {
                    alert_count += 1;
                    matched_specific = true;
                    let value = caps.get(0).map_or("", |m| m.as_str());
                    let prefix: String = value.chars().take(4).collect();
                    let masked = format!("{}***", prefix);
                    if !config.quiet {
                        println!("[CRITICAL] {}:{} - Specific pattern match [{}] -> {}", file_ident, index + 1, name, masked);
                    }
                    local_alerts.push(format_json_output(file_ident, index + 1, alert_type, name, &masked));
                    break;
                }
            }

            if matched_specific { continue; }

            if let Some(caps) = re_secrets.captures(&line) {
                alert_count += 1;
                let keyword = caps.get(1).map_or("", |m| m.as_str());
                let value = caps.get(2).map_or("", |m| m.as_str());
                let prefix: String = value.chars().take(4).collect();
                let masked = if value.chars().count() > 4 { format!("{}***", prefix) } else { "***".to_string() };

                if !config.quiet {
                    println!("[WARNING] {}:{} - Suspect pattern [{}] -> {}", file_ident, index + 1, keyword, masked);
                }
                local_alerts.push(format_json_output(file_ident, index + 1, "RegexMatch", keyword, &masked));
            }

            let line_lower = line.to_lowercase();
            let has_context = context_indicators.iter().any(|&ind| line_lower.contains(ind));

            if has_context {
                for word in line.split_whitespace() {
                    if word.len() >= 12 && !word.contains('/') && !word.contains('-') && !word.contains('.') && !word.contains('#') && !word.contains('%') {
                        let mut should_ignore = false;
                        let word_lower = word.to_lowercase();
                        for excluded in &whitelist {
                            if word_lower.contains(excluded) {
                                should_ignore = true;
                                break;
                            }
                        }

                        if !should_ignore {
                            let current_entropy = calculate_shannon_entropy(word);
                            if current_entropy > 4.85 {
                                alert_count += 1;
                                let prefix: String = word.chars().take(4).collect();
                                let masked = format!("{}***", prefix);
                                if !config.quiet {
                                    println!("[NOTICE] {}:{} - High entropy string ({}): {}", file_ident, index + 1, current_entropy, masked);
                                }
                                local_alerts.push(format_json_output(file_ident, index + 1, "HighEntropy", "Key/Password", &masked));
                            }
                        }
                    }
                }
            }
        }
    }

    if !local_alerts.is_empty() {
        let mut lock = report_list.lock().unwrap();
        lock.extend(local_alerts);
    }

    Ok(alert_count)
}

fn analyze_target_file(
    path: &Path, 
    re_secrets: &Regex, 
    re_ssh: &Regex, 
    specific_patterns: &[(Regex, &str, &str)], 
    report_list: &Arc<Mutex<Vec<String>>>,
    config: &ScanConfig
) -> io::Result<usize> {
    if !path.exists() || path.is_dir() { return Ok(0); }

    if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        let excluded_extensions = vec!["so", "bin", "exe", "dll", "png", "jpg", "zip", "tar", "gz", "lock", "db", "final"];
        if excluded_extensions.contains(&ext_str.as_str()) {
            return Ok(0);
        }
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    
    let reader = io::BufReader::new(file);
    let file_ident = path.file_name().unwrap_or_default().to_string_lossy();
    
    analyze_stream(reader, &file_ident, re_secrets, re_ssh, specific_patterns, report_list, config)
}

fn load_ignore_list() -> Vec<String> {
    let mut ignores = vec!["target".to_string(), ".git".to_string(), ".cache".to_string(), "node_modules".to_string()];
    if let Ok(file) = File::open(".shadowignore") {
        let reader = io::BufReader::new(file);
        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                ignores.push(trimmed.to_string());
            }
        }
    }
    ignores
}

fn collect_files_recursive(dir: &Path, list: &mut Vec<PathBuf>, ignore_list: &[String]) {
    if dir.is_dir() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                
                if ignore_list.contains(&name) {
                    continue;
                }

                if path.is_dir() {
                    collect_files_recursive(&path, list, ignore_list);
                } else {
                    list.push(path);
                }
            }
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let config = ScanConfig {
        quiet: args.contains(&"--quiet".to_string()),
        verbose: args.contains(&"--verbose".to_string()),
    };

    if !config.quiet {
        println!("=== SHADOW_SCAN v1.1 : Enterprise Advanced ===");
    }
    
    let json_reports = Arc::new(Mutex::new(Vec::new()));
    let re_secrets = Regex::new(r#"(?i)(password|passwd|secret|api_key|token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{6,})['"]?"#).unwrap();
    let re_ssh = Regex::new(r#"-----BEGIN (RSA|OPENSSH|PRIVATE|PGP) KEY-----"#).unwrap();

    let specific_patterns = vec![
        (Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(), "GitHub Personal Access Token", "GitHubToken"),
        (Regex::new(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(), "AWS Access Key ID", "AWSAccessKey"),
        (Regex::new(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}").unwrap(), "Slack Token", "SlackToken"),
    ];

    let mut total_alerts = 0;
    let ignore_list = load_ignore_list();

    let home_dir = dirs::home_dir().unwrap_or_default();
    let mut history_path = home_dir.join(".zsh_history");
    if !history_path.exists() { history_path = home_dir.join(".bash_history"); }
    if history_path.exists() {
        let history_name = history_path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if !ignore_list.contains(&history_name) {
            if config.verbose { println!("[INFO] Analyzing local shell history..."); }
            total_alerts += analyze_target_file(&history_path, &re_secrets, &re_ssh, &specific_patterns, &json_reports, &config)?;
        } else if config.verbose {
            println!("[INFO] Local shell history ignored (.shadowignore)");
        }
    }

    if Path::new(".git").exists() {
        if config.verbose { println!("[INFO] Git repository detected. Analyzing commit history (Time Travel)..."); }
        if let Ok(output) = Command::new("git").args(["log", "-p"]).output() {
            let cursor = Cursor::new(output.stdout);
            let reader = io::BufReader::new(cursor);
            total_alerts += analyze_stream(reader, "GIT_HISTORY", &re_secrets, &re_ssh, &specific_patterns, &json_reports, &config).unwrap_or(0);
        }
    }

    let mut files_to_scan = Vec::new();
    collect_files_recursive(Path::new("."), &mut files_to_scan, &ignore_list);

    if config.verbose && !config.quiet { 
        println!("[INFO] Parallel scanning of {} physical files...", files_to_scan.len()); 
    }

    let workspace_alerts: usize = files_to_scan.par_iter()
        .map(|path| analyze_target_file(path, &re_secrets, &re_ssh, &specific_patterns, &json_reports, &config).unwrap_or(0))
        .sum();
    total_alerts += workspace_alerts;

    let reports = json_reports.lock().unwrap();
    if !reports.is_empty() {
        let mut report_file = File::create("audit_report.json")?;
        let final_json = format!("[\n{}\n]", reports.join(",\n"));
        report_file.write_all(final_json.as_bytes())?;
        if !config.quiet { println!("[INFO] Audit report updated: audit_report.json"); }
    }

    if !config.quiet {
        println!("=== Scan Complete. Total: {} alert(s) found. ===", total_alerts);
    }

    if total_alerts > 0 {
        if !config.quiet { println!("[!] Secrets detected. Exiting with code 1 to block CI/CD pipeline."); }
        exit(1);
    } else {
        if !config.quiet { println!("[✓] Workspace is clean. Exiting with code 0."); }
        exit(0);
    }
}
