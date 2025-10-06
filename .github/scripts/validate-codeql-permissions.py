#!/usr/bin/env python3
"""
Validate that CodeQL workflows have correct permissions configuration.

This script ensures that any GitHub Actions workflow job that uses 
'github/codeql-action/analyze' has the 'security-events: write' permission 
defined at the job-level, not at the root-level.

This helps maintain security best practices by following the principle of 
least privilege for GitHub Actions permissions.
"""

import yaml
import sys
from pathlib import Path


def validate_codeql_permissions(workflow_path):
    """
    Validate CodeQL permissions in a single workflow file.
    
    Args:
        workflow_path: Path to the workflow YAML file
        
    Returns:
        tuple: (is_valid, violations) where violations is a list of error messages
    """
    violations = []
    
    try:
        with open(workflow_path, 'r') as f:
            workflow = yaml.safe_load(f)
    except Exception as e:
        violations.append(f"Failed to parse YAML: {e}")
        return False, violations
    
    if not workflow or 'jobs' not in workflow:
        # No jobs = no violations
        return True, violations
    
    # Find jobs that use github/codeql-action/analyze
    codeql_analyze_jobs = []
    for job_name, job_config in workflow['jobs'].items():
        if 'steps' in job_config:
            for step in job_config['steps']:
                if isinstance(step, dict) and 'uses' in step:
                    if 'github/codeql-action/analyze' in step['uses']:
                        codeql_analyze_jobs.append(job_name)
                        break
    
    if not codeql_analyze_jobs:
        # No CodeQL analyze jobs = no violations
        return True, violations
    
    # Check root-level permissions
    root_permissions = workflow.get('permissions', {})
    if isinstance(root_permissions, dict) and 'security-events' in root_permissions:
        if root_permissions['security-events'] == 'write':
            violations.append(
                "VIOLATION: Root-level permissions include 'security-events: write'. "
                "This permission should be defined at the job-level for jobs using CodeQL analyze."
            )
    
    # Check job-level permissions for CodeQL jobs
    for job_name in codeql_analyze_jobs:
        job_config = workflow['jobs'][job_name]
        job_permissions = job_config.get('permissions', {})
        
        if not isinstance(job_permissions, dict):
            violations.append(
                f"VIOLATION: Job '{job_name}' does not have proper permissions configuration"
            )
            continue
            
        if 'security-events' not in job_permissions:
            violations.append(
                f"VIOLATION: Job '{job_name}' uses CodeQL analyze but lacks 'security-events' permission"
            )
        elif job_permissions['security-events'] != 'write':
            violations.append(
                f"VIOLATION: Job '{job_name}' has 'security-events: {job_permissions['security-events']}' "
                f"but should be 'security-events: write'"
            )
    
    return len(violations) == 0, violations


def main():
    """Main validation function."""
    # Determine repository root
    script_path = Path(__file__).resolve()
    repo_root = script_path.parent.parent.parent
    workflows_dir = repo_root / '.github' / 'workflows'
    
    if not workflows_dir.exists():
        print(f"❌ ERROR: Workflows directory not found: {workflows_dir}")
        sys.exit(1)
    
    # Find all workflow files
    workflow_files = list(workflows_dir.glob('*.yml')) + list(workflows_dir.glob('*.yaml'))
    
    print(f"🔍 Validating CodeQL permissions in {len(workflow_files)} workflow files...")
    print()
    
    total_violations = 0
    workflows_with_codeql = 0
    
    for workflow_file in sorted(workflow_files):
        relative_path = workflow_file.relative_to(repo_root)
        
        is_valid, violations = validate_codeql_permissions(workflow_file)
        
        # Check if this workflow uses CodeQL analyze
        try:
            with open(workflow_file, 'r') as f:
                content = f.read()
                if 'github/codeql-action/analyze' in content:
                    workflows_with_codeql += 1
                    print(f"📋 {relative_path} (contains CodeQL analyze)")
                else:
                    print(f"📄 {relative_path}")
        except:
            print(f"❌ {relative_path} (error reading file)")
        
        if violations:
            total_violations += len(violations)
            for violation in violations:
                print(f"   ❌ {violation}")
        else:
            if workflows_with_codeql > 0 and 'github/codeql-action/analyze' in open(workflow_file).read():
                print(f"   ✅ CodeQL permissions correctly configured")
        
        print()
    
    # Summary
    print("=" * 70)
    print("📊 VALIDATION SUMMARY:")
    print(f"   • Total workflow files: {len(workflow_files)}")
    print(f"   • Workflows with CodeQL analyze: {workflows_with_codeql}")
    print(f"   • Total violations found: {total_violations}")
    
    if total_violations == 0:
        print("   ✅ All CodeQL workflows have correct permissions configuration!")
        sys.exit(0)
    else:
        print("   ❌ Found violations that need to be fixed!")
        sys.exit(1)


if __name__ == '__main__':
    main()