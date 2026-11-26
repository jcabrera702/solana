use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprBinary, ExprCast, ExprMethodCall, Field, ImplItemFn, ItemFn, ItemMod,
    ItemStruct, TraitItemFn,
};
use walkdir::WalkDir;

struct Finding {
    rule: &'static str,
    severity: &'static str,
    file: PathBuf,
    line: usize,
    snippet: String,
}

struct FileScanner<'a> {
    path: &'a Path,
    lines: Vec<&'a str>,
    findings: Vec<Finding>,
    in_function: bool,
}

impl<'a> FileScanner<'a> {
    fn new(path: &'a Path, content: &'a str) -> Self {
        Self {
            path,
            lines: content.lines().collect(),
            findings: Vec::new(),
            in_function: false,
        }
    }

    fn record(&mut self, rule: &'static str, severity: &'static str, line: usize) {
        let snippet = self
            .lines
            .get(line.saturating_sub(1))
            .map(|l| l.trim().chars().take(120).collect())
            .unwrap_or_default();

        self.findings.push(Finding {
            rule,
            severity,
            file: self.path.to_path_buf(),
            line,
            snippet,
        });
    }
}

fn has_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let mut is_test = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("test") {
                is_test = true;
            }
            Ok(())
        });
        is_test
    })
}

fn has_derive_accounts(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let mut is_accounts = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("Accounts") {
                is_accounts = true;
            }
            Ok(())
        });
        is_accounts
    })
}

fn inspect_account_field(scanner: &mut FileScanner, field: &Field) {
    let ty_str = quote::ToTokens::to_token_stream(&field.ty).to_string();
    let line = field.span().start().line;

    // Collect full attribute text regardless of how many lines #[account(...)] spans
    let mut attr_blob = String::new();
    let mut has_doc_check = false;

    for attr in &field.attrs {
        let tokens = quote::ToTokens::to_token_stream(attr).to_string();
        if attr.path().is_ident("doc") && tokens.contains("CHECK:") {
            has_doc_check = true;
        }
        attr_blob.push_str(&tokens);
        attr_blob.push(' ');
    }

    // SOL-002: init_if_needed reinitialization risk
    if attr_blob.contains("init_if_needed") {
        scanner.record("SOL-002", "HIGH", line);
    }

    // SOL-001A / SOL-001B: UncheckedAccount or raw AccountInfo
    if ty_str.contains("UncheckedAccount") || ty_str.contains("AccountInfo") {
        let has_strong_constraint = attr_blob.contains("seeds =")
            || attr_blob.contains("address =")
            || attr_blob.contains("owner =");

        if !has_strong_constraint {
            if has_doc_check || attr_blob.contains("account") {
                scanner.record("SOL-001B", "INFO", line);
            } else {
                scanner.record("SOL-001A", "HIGH", line);
            }
        }
    }

    // SOL-008: Writable Anchor account with no relational or PDA constraints
    let is_mut = attr_blob.contains("mut");
    let has_any_guard = attr_blob.contains("init")
        || attr_blob.contains("has_one")
        || attr_blob.contains("seeds =")
        || attr_blob.contains("address =")
        || attr_blob.contains("owner =")
        || attr_blob.contains("constraint =");

    if is_mut && !has_any_guard {
        scanner.record("SOL-008", "HIGH", line);
    }
}

impl<'ast, 'a> Visit<'ast> for FileScanner<'a> {
    // Skip #[cfg(test)] modules cleanly without stopping the rest of the file
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let was_in_fn = self.in_function;
        self.in_function = true;
        visit::visit_item_fn(self, node);
        self.in_function = was_in_fn;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let was_in_fn = self.in_function;
        self.in_function = true;
        visit::visit_impl_item_fn(self, node);
        self.in_function = was_in_fn;
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        let was_in_fn = self.in_function;
        self.in_function = true;
        visit::visit_trait_item_fn(self, node);
        self.in_function = was_in_fn;
    }

    // Inspect #[derive(Accounts)] structs directly
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if has_derive_accounts(&node.attrs) {
            for field in &node.fields {
                inspect_account_field(self, field);
            }
        }
        visit::visit_item_struct(self, node);
    }

    // SOL-003: Binary arithmetic in expressions (+, -, *, /, +=, -=, *=, /=)
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if self.in_function {
            use syn::BinOp::*;
            match node.op {
                Add(_) | Sub(_) | Mul(_) | Div(_) | AddAssign(_) | SubAssign(_) | MulAssign(_)
                | DivAssign(_) => {
                    self.record("SOL-003", "MEDIUM", node.span().start().line);
                }
                _ => {}
            }
        }
        visit::visit_expr_binary(self, node);
    }

    // SOL-004: .unwrap() / .expect()
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method == "unwrap" || method == "expect" {
            self.record("SOL-004", "LOW", node.span().start().line);
        }
        visit::visit_expr_method_call(self, node);
    }

    // SOL-005 & SOL-006: remaining_accounts and invoke / invoke_signed
    fn visit_expr(&mut self, node: &'ast Expr) {
        match node {
            Expr::Field(f) => {
                if let syn::Member::Named(ident) = &f.member {
                    if ident == "remaining_accounts" {
                        self.record("SOL-005", "HIGH", f.span().start().line);
                    }
                }
            }
            Expr::Call(call) => {
                let func_str = quote::ToTokens::to_token_stream(&call.func).to_string();
                if func_str.ends_with("invoke") || func_str.ends_with("invoke_signed") {
                    self.record("SOL-006", "HIGH", call.span().start().line);
                }
                if func_str.ends_with("next_account_info") {
                    self.record("SOL-009", "INFO", call.span().start().line);
                }
            }
            _ => {}
        }
        visit::visit_expr(self, node);
    }

    // SOL-007: Narrowing integer casts (as u64, as u32, as u16, as u8)
    fn visit_expr_cast(&mut self, node: &'ast ExprCast) {
        let target_ty = quote::ToTokens::to_token_stream(&node.ty).to_string();
        if matches!(target_ty.as_str(), "u64" | "u32" | "u16" | "u8") {
            self.record("SOL-007", "MEDIUM", node.span().start().line);
        }
        visit::visit_expr_cast(self, node);
    }
}

fn scan_file(path: &Path) -> Vec<Finding> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(syntax_tree) = syn::parse_file(&content) else {
        eprintln!("Warning: could not parse Rust syntax in {}", path.display());
        return Vec::new();
    };

    let mut scanner = FileScanner::new(path, &content);
    scanner.visit_file(&syntax_tree);
    scanner.findings
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(target) = args.next() else {
        eprintln!("Usage: cargo run -- <path_to_programs_dir>");
        std::process::exit(1);
    };
    let high_only = args.any(|arg| arg == "--high");

    let target_path = Path::new(&target);
    if !target_path.exists() {
        eprintln!("Error: target path does not exist: {}", target_path.display());
        std::process::exit(1);
    }

    let mut rs_files = Vec::new();
    for entry in WalkDir::new(target_path).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let is_ignored = path.components().any(|c| {
            let name = c.as_os_str();
            name == "target" || name == "tests"
        });
        if !is_ignored && path.extension().and_then(|s| s.to_str()) == Some("rs") {
            rs_files.push(path.to_path_buf());
        }
    }

    let mut all_findings = Vec::new();
    for file in &rs_files {
        all_findings.extend(scan_file(file));
    }

    let high_count = all_findings.iter().filter(|f| f.severity == "HIGH").count();
    let med_count = all_findings.iter().filter(|f| f.severity == "MEDIUM").count();
    let low_count = all_findings.iter().filter(|f| f.severity == "LOW").count();
    let info_count = all_findings.iter().filter(|f| f.severity == "INFO").count();

    println!(
        "Scanned {} Rust files | Total: {} (HIGH: {}, MEDIUM: {}, LOW: {}, INFO: {})\n",
        rs_files.len(),
        all_findings.len(),
        high_count,
        med_count,
        low_count,
        info_count
    );

    for f in all_findings {
        if high_only && f.severity != "HIGH" {
            continue;
        }
        println!("[{}] {} — {}:{}", f.severity, f.rule, f.file.display(), f.line);
        println!("    {}", f.snippet);
    }
}