#!/usr/bin/env python3
"""
AIVerify - AI Code Verification Tool
Catches AI hallucinations and security issues in generated code.
Version: 0.3.0 - Focus on high-accuracy detections
"""

import re
import sys
import argparse
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

VERSION = "0.3.0"

@dataclass
class CodeIssue:
    """Represents a detected code issue."""
    file: str
    line: int
    severity: str
    rule: str
    message: str
    fix_suggestion: Optional[str] = None
    
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    
    def __repr__(self):
        return f"{self.file}:{self.line} [{self.severity}] {self.rule}: {self.message}"


class SecurityScanner:
    """High-accuracy security vulnerability detection."""
    
    PATTERNS = {
        # Hardcoded secrets - excludes common constants
        'hardcoded_secret': {
            'pattern': r'(?!.*(_EXAMPLE|_PLACEHOLDER|your_|STATIC_|PUBLIC_|CONSTANT_|_TEST))([a-z_]*)(api[_-]?key|password|secret|token|auth[_-]?token|private[_-]?key)\s*=\s*["\'][\w\-/+=]{20,}["\']',
            'severity': CodeIssue.SEVERITY_CRITICAL,
            'message': 'Hardcoded secret detected (20+ chars)',
            'fix': 'Use environment variables: os.environ.get("API_KEY")'
        },
        # Command injection
        'command_injection': {
            'pattern': r'(subprocess\.(call|run|Popen)|os\.system)\s*\([^)]*(\+|%|f["\'])',
            'severity': CodeIssue.SEVERITY_CRITICAL,
            'message': 'Command injection via string concatenation',
            'fix': 'Use subprocess with shell=False and list args'
        },
        # Insecure deserialization
        'insecure_deser': {
            'pattern': r'(pickle\.loads|yaml\.load(?!_safe)|marshal\.loads)\s*\(',
            'severity': CodeIssue.SEVERITY_CRITICAL,
            'message': 'Insecure deserialization - RCE risk',
            'fix': 'Use yaml.safe_load() or json.loads() instead'
        },
        # SQL injection via f-strings
        'sql_injection': {
            'pattern': r'(execute|query|cursor\.execute)\s*\([^)]*f["\'][^"\']*\{',
            'severity': CodeIssue.SEVERITY_CRITICAL,
            'message': 'SQL injection via f-string interpolation',
            'fix': 'Use parameterized queries: cursor.execute("SELECT * WHERE id=%s", (id,))'
        },
        # SSRF
        'ssrf': {
            'pattern': r'requests\.(get|post)\s*\([^)]*\{|requests\.(get|post)\s*\([^)]*input\(',
            'severity': CodeIssue.SEVERITY_HIGH,
            'message': 'Potential SSRF - user input in HTTP request',
            'fix': 'Validate and whitelist allowed domains'
        },
        # Path traversal
        'path_traversal': {
            'pattern': r'open\s*\([^)]*\+.*["\'][.\/]',
            'severity': CodeIssue.SEVERITY_HIGH,
            'message': 'Potential path traversal via string concatenation',
            'fix': 'Use os.path.join() and validate inputs'
        },
    }
    
    def scan(self, content: str, filepath: str) -> List[CodeIssue]:
        """Scan content for security issues."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and pattern definitions
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if 'pattern' in line and ('r"' in line or "r'" in line):
                continue
            
            for rule_name, rule in self.PATTERNS.items():
                if re.search(rule['pattern'], line, re.IGNORECASE):
                    issues.append(CodeIssue(
                        file=filepath,
                        line=line_num,
                        severity=rule['severity'],
                        rule=rule_name,
                        message=rule['message'],
                        fix_suggestion=rule['fix']
                    ))
        
        return issues


class AIVerifier:
    """Main verification engine."""
    
    def __init__(self, verbose: bool = False):
        self.security_scanner = SecurityScanner()
        self.verbose = verbose
    
    def scan_file(self, filepath: Path) -> List[CodeIssue]:
        """Scan a single file."""
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            return self.security_scanner.scan(content, str(filepath))
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {filepath}: {e}", file=sys.stderr)
            return []
    
    def scan_directory(self, path: Path, extensions: List[str] = None) -> List[CodeIssue]:
        """Scan all files in directory."""
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.go', '.rs', '.php']
        
        all_issues = []
        file_count = 0
        
        for ext in extensions:
            for filepath in path.rglob(f'*{ext}'):
                if any(part in filepath.parts for part in 
                       ['.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build']):
                    continue
                
                file_count += 1
                issues = self.scan_file(filepath)
                all_issues.extend(issues)
        
        if self.verbose:
            print(f"Scanned {file_count} files", file=sys.stderr)
        
        return all_issues
    
    def format_results(self, issues: List[CodeIssue], show_fixes: bool = True) -> str:
        """Format issues for display."""
        if not issues:
            return "✅ No critical security issues found!"
        
        critical = [i for i in issues if i.severity == CodeIssue.SEVERITY_CRITICAL]
        high = [i for i in issues if i.severity == CodeIssue.SEVERITY_HIGH]
        
        output = []
        output.append(f"\n🔍 AIVerify found {len(issues)} security issue(s):\n")
        
        if critical:
            output.append(f"🚨 CRITICAL ({len(critical)}):")
            for issue in critical:
                output.append(f"  ❌ {issue}")
                if show_fixes and issue.fix_suggestion:
                    output.append(f"     💡 {issue.fix_suggestion}")
        
        if high:
            output.append(f"\n⚠️  HIGH ({len(high)}):")
            for issue in high:
                output.append(f"  ⚠️  {issue}")
                if show_fixes and issue.fix_suggestion:
                    output.append(f"     💡 {issue.fix_suggestion}")
        
        return '\n'.join(output)


def init_git_hook():
    """Initialize pre-commit hook."""
    git_dir = Path('.git')
    if not git_dir.exists():
        print("❌ Not a git repository. Run 'git init' first.")
        return False
    
    hooks_dir = git_dir / 'hooks'
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / 'pre-commit'
    
    hook_content = """#!/bin/sh
# AIVerify pre-commit hook
aiverify . --fail-on-critical
"""
    
    hook_path.write_text(hook_content)
    hook_path.chmod(0o755)
    
    print("✅ AIVerify pre-commit hook installed!")
    return True


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='AIVerify v0.3 - High-accuracy security scanner for AI-generated code'
    )
    
    parser.add_argument('path', nargs='?', default='.', help='File or directory to scan')
    parser.add_argument('--init', action='store_true', help='Initialize git pre-commit hook')
    parser.add_argument('--fail-on-critical', action='store_true', help='Exit 1 if critical issues found')
    parser.add_argument('--no-fixes', action='store_true', help='Hide fix suggestions')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version=f'AIVerify {VERSION}')
    
    args = parser.parse_args()
    
    if args.init:
        sys.exit(0 if init_git_hook() else 1)
    
    path = Path(args.path)
    if not path.exists():
        print(f"❌ Path not found: {path}")
        sys.exit(1)
    
    verifier = AIVerifier(verbose=args.verbose)
    
    if path.is_file():
        issues = verifier.scan_file(path)
    else:
        issues = verifier.scan_directory(path)
    
    print(verifier.format_results(issues, show_fixes=not args.no_fixes))
    
    if args.fail_on_critical:
        critical_count = sum(1 for i in issues if i.severity == CodeIssue.SEVERITY_CRITICAL)
        sys.exit(1 if critical_count > 0 else 0)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
