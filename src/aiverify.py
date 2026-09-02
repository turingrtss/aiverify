#!/usr/bin/env python3
"""
AIVerify - AI Code Verification Tool
Catches AI hallucinations and security issues in generated code.
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple

class CodeIssue:
    """Represents a detected code issue."""
    
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    
    def __init__(self, file: str, line: int, severity: str, rule: str, message: str):
        self.file = file
        self.line = line
        self.severity = severity
        self.rule = rule
        self.message = message
    
    def __repr__(self):
        return f"{self.file}:{self.line} [{self.severity}] {self.rule}: {self.message}"


class AIVerifier:
    """Main verification engine."""
    
    # AI hallucination patterns - common mistakes AI makes
    AI_PATTERNS = [
        # Non-existent Python APIs
        (r'from\s+(\w+)\s+import\s+(\w+)', 'check_import_exists'),
        # Hardcoded secrets
        (r'(api[_-]?key|password|secret|token)\s*=\s*["\'][\w\-/+=]{16,}["\']', 'hardcoded_secret'),
        # SQL injection vectors
        (r'execute\([^)]*%s|execute\([^)]*\+|execute\(f["\']', 'sql_injection'),
        # Dangerous eval/exec
        (r'\beval\(|\bexec\(', 'dangerous_eval'),
        # Missing null checks after AI suggestions
        (r'(\w+)\s*=\s*None.*\n.*\1\.', 'null_deref'),
    ]
    
    def __init__(self):
        self.issues: List[CodeIssue] = []
    
    def scan_file(self, filepath: Path) -> List[CodeIssue]:
        """Scan a single file for issues."""
        issues = []
        
        try:
            content = filepath.read_text(encoding='utf-8')
            lines = content.split('\n')
            
            # Check each pattern
            for line_num, line in enumerate(lines, 1):
                # Hardcoded secrets
                if re.search(self.AI_PATTERNS[1][0], line, re.IGNORECASE):
                    issues.append(CodeIssue(
                        str(filepath),
                        line_num,
                        CodeIssue.SEVERITY_CRITICAL,
                        "hardcoded-secret",
                        "Hardcoded API key or secret detected"
                    ))
                
                # SQL injection
                if re.search(self.AI_PATTERNS[2][0], line):
                    issues.append(CodeIssue(
                        str(filepath),
                        line_num,
                        CodeIssue.SEVERITY_CRITICAL,
                        "sql-injection",
                        "Potential SQL injection vulnerability"
                    ))
                
                # Dangerous eval/exec
                if re.search(self.AI_PATTERNS[3][0], line):
                    issues.append(CodeIssue(
                        str(filepath),
                        line_num,
                        CodeIssue.SEVERITY_HIGH,
                        "dangerous-eval",
                        "Use of eval() or exec() is dangerous"
                    ))
            
            # Multi-line patterns (null deref)
            for match in re.finditer(self.AI_PATTERNS[4][0], content):
                line_num = content[:match.start()].count('\n') + 1
                issues.append(CodeIssue(
                    str(filepath),
                    line_num,
                    CodeIssue.SEVERITY_MEDIUM,
                    "null-deref",
                    "Potential null dereference after None assignment"
                ))
        
        except Exception as e:
            print(f"Error scanning {filepath}: {e}", file=sys.stderr)
        
        return issues
    
    def scan_directory(self, path: Path, extensions: List[str] = None) -> List[CodeIssue]:
        """Scan all files in directory."""
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.go', '.rs']
        
        all_issues = []
        
        for ext in extensions:
            for filepath in path.rglob(f'*{ext}'):
                # Skip common ignore patterns
                if any(part in filepath.parts for part in ['.git', 'node_modules', '__pycache__', 'venv', '.venv']):
                    continue
                
                issues = self.scan_file(filepath)
                all_issues.extend(issues)
        
        return all_issues
    
    def format_results(self, issues: List[CodeIssue]) -> str:
        """Format issues for display."""
        if not issues:
            return "✅ No issues found!"
        
        # Group by severity
        critical = [i for i in issues if i.severity == CodeIssue.SEVERITY_CRITICAL]
        high = [i for i in issues if i.severity == CodeIssue.SEVERITY_HIGH]
        medium = [i for i in issues if i.severity == CodeIssue.SEVERITY_MEDIUM]
        
        output = []
        output.append(f"\n🚨 AIVerify found {len(issues)} issue(s):\n")
        
        if critical:
            output.append(f"CRITICAL ({len(critical)}):")
            for issue in critical:
                output.append(f"  ❌ {issue}")
        
        if high:
            output.append(f"\nHIGH ({len(high)}):")
            for issue in high:
                output.append(f"  ⚠️  {issue}")
        
        if medium:
            output.append(f"\nMEDIUM ({len(medium)}):")
            for issue in medium:
                output.append(f"  ⚡ {issue}")
        
        return '\n'.join(output)


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: aiverify <path>")
        sys.exit(1)
    
    path = Path(sys.argv[1])
    verifier = AIVerifier()
    
    if path.is_file():
        issues = verifier.scan_file(path)
    else:
        issues = verifier.scan_directory(path)
    
    print(verifier.format_results(issues))
    
    # Exit with error code if critical issues found
    critical_count = sum(1 for i in issues if i.severity == CodeIssue.SEVERITY_CRITICAL)
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()
