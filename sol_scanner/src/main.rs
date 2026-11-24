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

fn has_anchor_guard(lines: &[&str], idx: usize) -> bool {
    let start = idx.saturating_sub(5);
    let window = lines[start..idx].join("\n");
    window.contains("/// CHECK:") || window.contains("#[account(")
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

        if (code_only.contains("UncheckedAccount") || code_only.contains("AccountInfo"))
            && !has_anchor_guard(&lines, idx)
        {
            findings.push(Finding {
                rule: "SOL-001",
                severity: "HIGH",
                file: path.to_path_buf(),
                line: line_num,
                snippet: snippet.clone(),
            });
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