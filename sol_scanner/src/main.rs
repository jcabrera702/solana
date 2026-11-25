use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

struct Finding {
    rule: &'static str,
    severity: &'static str,
    file: PathBuf,
    line: usize,
    snippet: String,
}

enum AccountGuard {
    StrongConstraint,
    ManualCheckOnly,
    Unguarded,
}

fn check_account_guard(lines: &[&str], idx: usize) -> AccountGuard {
    let start = idx.saturating_sub(8);
    let window = lines[start..idx].join("\n");
    if window.contains("seeds =") || window.contains("address =") || window.contains("owner =") {
        AccountGuard::StrongConstraint
    } else if window.contains("/// CHECK:") || window.contains("#[account(") {
        AccountGuard::ManualCheckOnly
    } else {
        AccountGuard::Unguarded
    }
}

fn has_arithmetic_op(line: &str) -> bool {
    // Simple starter check; avoids `->`, `=>`, `==`, `!=`, `<=`, `>=`
    let cleaned = line
        .replace("->", "")
        .replace("=>", "")
        .replace("==", "")
        .replace("!=", "")
        .replace("<=", "")
        .replace(">=", "");

    cleaned.contains(" + ")
        || cleaned.contains(" - ")
        || cleaned.contains(" * ")
        || cleaned.contains(" / ")
        || cleaned.contains("+=")
        || cleaned.contains("-=")
        || cleaned.contains("*=")
        || cleaned.contains("/=")
}

fn scan_file(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(content) = fs::read_to_string(path) else {
        return findings;
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut in_block_comment = false;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Handle multi-line /* ... */ block comments
        if in_block_comment {
            if let Some((_, rest)) = trimmed.split_once("*/") {
                in_block_comment = false;
                if rest.trim().is_empty() {
                    continue;
                }
            } else {
                continue;
            }
        }
        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("use ") {
            continue;
        }
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }

        let code_only = trimmed.split("//").next().unwrap_or("").trim();
        if code_only.is_empty() {
            continue;
        }

        let line_num = idx + 1;
        let snippet: String = code_only.chars().take(120).collect();

        if code_only.contains("UncheckedAccount") || code_only.contains("AccountInfo") {
            match check_account_guard(&lines, idx) {
                AccountGuard::Unguarded => findings.push(Finding {
                    rule: "SOL-001A",
                    severity: "HIGH",
                    file: path.to_path_buf(),
                    line: line_num,
                    snippet: snippet.clone(),
                }),
                AccountGuard::ManualCheckOnly => findings.push(Finding {
                    rule: "SOL-001B",
                    severity: "INFO",
                    file: path.to_path_buf(),
                    line: line_num,
                    snippet: snippet.clone(),
                }),
                AccountGuard::StrongConstraint => {}
            }
        }

        if code_only.contains("init_if_needed") {
            findings.push(Finding {
                rule: "SOL-002",
                severity: "HIGH",
                file: path.to_path_buf(),
                line: line_num,
                snippet: snippet.clone(),
            });
        }

        if has_arithmetic_op(code_only) {
            findings.push(Finding {
                rule: "SOL-003",
                severity: "MEDIUM",
                file: path.to_path_buf(),
                line: line_num,
                snippet: snippet.clone(),
            });
        }

        if code_only.contains(".unwrap(") || code_only.contains(".expect(") {
            findings.push(Finding {
                rule: "SOL-004",
                severity: "LOW",
                file: path.to_path_buf(),
                line: line_num,
                snippet,
            });
        }

        if code_only.contains("remaining_accounts") {
            findings.push(Finding {
                rule: "SOL-005",
                severity: "HIGH",
                file: path.to_path_buf(),
                line: line_num,
                snippet: snippet.clone(),
            });
        }

        if code_only.contains("invoke(") || code_only.contains("invoke_signed(") {
            findings.push(Finding {
                rule: "SOL-006",
                severity: "HIGH",
                file: path.to_path_buf(),
                line: line_num,
                snippet: snippet.clone(),
            });
        }

        if code_only.contains(" as u64")
            || code_only.contains(" as u32")
            || code_only.contains(" as u16")
            || code_only.contains(" as u8")
        {
            findings.push(Finding {
                rule: "SOL-007",
                severity: "MEDIUM",
                file: path.to_path_buf(),
                line: line_num,
                snippet,
            });
        }
    }

    findings
}

fn main() {
    
    let mut args = env::args().skip(1);
    let Some(target) = args.next() else {
        eprintln!("Usage: cargo run -- <path_to_programs_dir>");
        std::process::exit(1);
    };

    let mut rs_files = Vec::new();
    for entry in WalkDir::new(&target).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let is_in_target = path.components().any(|c| c.as_os_str() == "target");
        if !is_in_target && path.extension().and_then(|s| s.to_str()) == Some("rs") {
            rs_files.push(path.to_path_buf());
        }
    }

    let mut all_findings = Vec::new();
    for file in &rs_files {
        all_findings.extend(scan_file(file));
    }

    println!(
        "Scanned {} Rust files | Found {} potential leads\n",
        rs_files.len(),
        all_findings.len()
    );

    for f in all_findings {
        println!("[{}] {} — {}:{}", f.severity, f.rule, f.file.display(), f.line);
        println!("    {}", f.snippet);
    }
    
}