#!/usr/bin/env python3
"""
AIVerify - AI Code Verification Tool
Catches AI hallucinations and security issues in generated code.
Version: 0.1.0
"""

import re
import sys
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

VERSION = "0.1.0"

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
    SEVERITY_LOW = "LOW"
    
    def __repr__(self):
        return f"{self.file}:{self.line} [{self.severity}] {self.rule}: {self.message}"


class SecurityScanner:
    """Security vulnerability detection."""
    
    PATTERNS = {
        # Secrets and credentials
        'hardcoded_secret': {
            'pattern': r'(api[_-]?key|password|secret|token|auth[_-]?token)\s*=\s*["\'][\w\-/+=]{16,}["\']',
            'severity': CodeIssue.SEVERITY_CRITICAL,
            'message': 'Hardcoded secret detected',
            'fix': 'Use environment variables or a secrets manager'
        },
        # SQL injection
        'sql_injection': {
            'pattern': r'(execute|query)\s*\([^)]*(%s|%d|\+|f["\'])',
            'severity': CodeIssue.SEVERITY_CRITICAL,
            'message': 'Potential SQL injection vulnerability',
            'fix': 'Use parameterized queries or an ORM'
        },
        # Command injection
        'command_injection': {
            'pattern': r'(subprocess\.(call|run|Popen)|os\.system|exec)\s*\([^)]*\+',
            'severity': CodeIssue.SEVERITY_CRITICAL,
            'message': 'Potential command injection',
            'fix': 'Use shell=False and pass args as list'
        },
        # Dangerous functions
        'dangerous_eval': {
            'pattern': r'\b(eval|exec)\s*\(',
            'severity': CodeIssue.SEVERITY_HIGH,
            'message': 'Dangerous eval() or exec() usage',
            'fix': 'Use ast.literal_eval() or safer alternatives'
        },
        # Path traversal
        'path_traversal': {
            'pattern': r'open\s*\([^)]*\+',
            'severity': CodeIssue.SEVERITY_HIGH,
            'message': 'Potential path traversal vulnerability',
            'fix': 'Validate and sanitize file paths'
        },
        # Weak crypto
        'weak_crypto': {
            'pattern': r'\b(md5|sha1)\s*\(',
            'severity': CodeIssue.SEVERITY_MEDIUM,
            'message': 'Weak cryptographic algorithm',
            'fix': 'Use SHA-256 or stronger'
        },
    }
    
    def scan(self, content: str, filepath: str) -> List[CodeIssue]:
        """Scan content for security issues."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            
            # Skip regex pattern definitions (to avoid self-flagging)
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


class AIHallucinationDetector:
    """Detects common AI coding mistakes."""
    
    PATTERNS = {
        # Null pointer dereference
        'null_deref': {
            'pattern': r'(\w+)\s*=\s*None.*\n.*\1\.',
            'severity': CodeIssue.SEVERITY_MEDIUM,
            'message': 'Potential null dereference',
            'fix': 'Add null check before accessing'
        },
        # Infinite loop patterns AI often generates
        'infinite_loop': {
            'pattern': r'while\s+True:.*\n(?:(?!break|return).)*$',
            'severity': CodeIssue.SEVERITY_HIGH,
            'message': 'Potential infinite loop without break',
            'fix': 'Add break condition or timeout'
        },
        # Missing error handling on network calls
        'missing_error_handling': {
            'pattern': r'requests\.(get|post|put|delete)\([^)]+\)\s*$',
            'severity': CodeIssue.SEVERITY_MEDIUM,
            'message': 'Network call without error handling',
            'fix': 'Wrap in try-except block'
        },
    }
    
    def scan(self, content: str, filepath: str) -> List[CodeIssue]:
        """Scan for AI hallucination patterns."""
        issues = []
        
        for rule_name, rule in self.PATTERNS.items():
            for match in re.finditer(rule['pattern'], content, re.MULTILINE):
                line_num = content[:match.start()].count('\n') + 1
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
        self.hallucination_detector = AIHallucinationDetector()
        self.verbose = verbose
    
    def scan_file(self, filepath: Path) -> List[CodeIssue]:
        """Scan a single file."""
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            
            issues = []
            issues.extend(self.security_scanner.scan(content, str(filepath)))
            issues.extend(self.hallucination_detector.scan(content, str(filepath)))
            
            return issues
            
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
                # Skip common ignore patterns
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
            return "✅ No issues found! Your code looks clean."
        
        # Group by severity
        critical = [i for i in issues if i.severity == CodeIssue.SEVERITY_CRITICAL]
        high = [i for i in issues if i.severity == CodeIssue.SEVERITY_HIGH]
        medium = [i for i in issues if i.severity == CodeIssue.SEVERITY_MEDIUM]
        low = [i for i in issues if i.severity == CodeIssue.SEVERITY_LOW]
        
        output = []
        output.append(f"\n🔍 AIVerify found {len(issues)} issue(s):\n")
        
        if critical:
            output.append(f"🚨 CRITICAL ({len(critical)}):")
            for issue in critical:
                output.append(f"  ❌ {issue}")
                if show_fixes and issue.fix_suggestion:
                    output.append(f"     💡 Fix: {issue.fix_suggestion}")
        
        if high:
            output.append(f"\n⚠️  HIGH ({len(high)}):")
            for issue in high:
                output.append(f"  ⚠️  {issue}")
                if show_fixes and issue.fix_suggestion:
                    output.append(f"     💡 Fix: {issue.fix_suggestion}")
        
        if medium:
            output.append(f"\n⚡ MEDIUM ({len(medium)}):")
            for issue in medium:
                output.append(f"  ⚡ {issue}")
                if show_fixes and issue.fix_suggestion:
                    output.append(f"     💡 Fix: {issue.fix_suggestion}")
        
        if low:
            output.append(f"\n📝 LOW ({len(low)}):")
            for issue in low:
                output.append(f"  📝 {issue}")
        
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
    print("   Commits with CRITICAL issues will be blocked.")
    return True


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='AIVerify - Catch AI-generated bugs before they ship',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aiverify .                    # Scan current directory
  aiverify src/main.py          # Scan specific file
  aiverify . --fail-on-critical # Exit 1 if critical issues found
  aiverify init                 # Set up pre-commit hook
        """
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
    
    # Determine exit code
    if args.fail_on_critical:
        critical_count = sum(1 for i in issues if i.severity == CodeIssue.SEVERITY_CRITICAL)
        sys.exit(1 if critical_count > 0 else 0)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

# aiverify: disable
