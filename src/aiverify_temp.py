    def scan(self, content: str, filepath: str) -> List[CodeIssue]:
        """Scan content for security issues."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments, imports, pattern definitions, function definitions
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if stripped.startswith(('import ', 'from ')):
                continue
            if stripped.startswith('def ') and 'render_template_string' in stripped:
                continue  # Skip function definitions
            if 'pattern' in line and ('r"' in line or "r'" in line):
                continue
