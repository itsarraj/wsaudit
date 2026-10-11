use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Pass,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn badge(&self) -> ColoredString {
        match self {
            Severity::Pass => " PASS ".on_green().bold().white(),
            Severity::Info => " INFO ".on_blue().bold().white(),
            Severity::Low => " LOW ".on_cyan().bold().white(),
            Severity::Medium => " MED ".on_yellow().bold().black(),
            Severity::High => " HIGH ".on_bright_red().bold().white(),
            Severity::Critical => " CRIT ".on_red().bold().white(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub target_url: String,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    pub fn new(target_url: String) -> Self {
        Self {
            target_url,
            findings: Vec::new(),
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn has_vulnerabilities(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity >= Severity::Medium)
    }

    pub fn print_summary(&self) {
        println!(
            "\n{}",
            "=================== WebSocket Security Audit Report ==================="
                .bold()
                .cyan()
        );
        println!("Target URL: {}", self.target_url.bold());
        println!("Checks Run: {}", self.findings.len());

        let high_count = self
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .count();
        let med_count = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let pass_count = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Pass)
            .count();

        println!(
            "Summary:    {} passed, {} high/critical, {} medium\n",
            pass_count.to_string().green(),
            high_count.to_string().red().bold(),
            med_count.to_string().yellow()
        );

        for finding in &self.findings {
            let badge = finding.severity.badge();
            println!("{} {} [{}]", badge, finding.title.bold(), finding.id);
            println!("       {}", finding.description);
            if finding.severity > Severity::Pass && !finding.remediation.is_empty() {
                println!("       {} {}", "Fix:".bold().yellow(), finding.remediation);
            }
            println!();
        }

        if self.has_vulnerabilities() {
            println!(
                "{}",
                "Result: VULNERABILITIES DETECTED (Exit code 1)".bold().red()
            );
        } else {
            println!(
                "{}",
                "Result: CLEAN (No high/medium vulnerabilities detected)".bold().green()
            );
        }
        println!(
            "{}",
            "======================================================================="
                .bold()
                .cyan()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_evaluation() {
        let mut report = AuditReport::new("ws://localhost:8080".to_string());
        report.add(Finding {
            id: "tls_missing".to_string(),
            severity: Severity::Low,
            title: "Cleartext WebSocket".to_string(),
            description: "Target uses ws://".to_string(),
            remediation: "Use wss://".to_string(),
        });
        assert!(!report.has_vulnerabilities());

        report.add(Finding {
            id: "cswsh_untrusted".to_string(),
            severity: Severity::High,
            title: "CSWSH Detected".to_string(),
            description: "Arbitrary origin accepted".to_string(),
            remediation: "Validate Origin header".to_string(),
        });
        assert!(report.has_vulnerabilities());
    }
}
