#!/usr/bin/env python3
"""
Mermaid Diagram to PNG Converter Script

This script extracts Mermaid diagrams from markdown files and converts them
to PNG format using the mermaid-cli tool (mmdc).

Usage:
    python mermaid_to_png.py
    python mermaid_to_png.py --output-dir ./diagrams/
    python mermaid_to_png.py --input-file ./path/to/diagram.md
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

def extract_mermaid_diagram(file_path: str) -> Optional[str]:
    """Extract Mermaid diagram content from markdown file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to match ```mermaid...``` codeblocks
        pattern = r'```mermaid\s*\n(.*?)\n```'
        matches = re.findall(pattern, content, re.DOTALL)
        
        if matches:
            # Return the first Mermaid diagram found
            return matches[0].strip()
        else:
            print(f"No Mermaid diagram found in {file_path}", file=sys.stderr)
            return None
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error reading file {file_path}: {e}", file=sys.stderr)
        return None

def check_mermaid_cli():
    """Check if mermaid-cli (mmdc) is installed"""
    try:
        result = subprocess.run(['mmdc', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"Found mermaid-cli version: {result.stdout.strip()}")
            return True
        else:
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def convert_mermaid_to_png(mermaid_content: str, output_path: str) -> bool:
    """Convert Mermaid diagram to PNG using mermaid-cli"""
    try:
        # Create temporary file for Mermaid content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as temp_file:
            temp_file.write(mermaid_content)
            temp_mmd_path = temp_file.name
        
        try:
            # Build mmdc command with high quality settings
            cmd = ['mmdc', '-i', temp_mmd_path, '-o', output_path, '-b', 'white', '--scale', '3', '--width', '2400', '--height', '1800']
            
            # Run mermaid-cli
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print(f"Successfully converted Mermaid diagram to PNG: {output_path}")
                return True
            else:
                print(f"Error running mmdc: {result.stderr}", file=sys.stderr)
                return False
                
        finally:
            # Clean up temporary file
            os.unlink(temp_mmd_path)
            
    except subprocess.TimeoutExpired:
        print("Error: mermaid-cli conversion timed out", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error converting Mermaid diagram: {e}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Convert Mermaid diagrams from markdown files to PNG format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mermaid_to_png.py --output-dir ./diagrams/
  python mermaid_to_png.py --input-file ./path/to/diagram.md
        """
    )
    
    parser.add_argument('--output-dir',
                       default='./Reporting/Guard/images/',
                       help='Output directory where the PNG will be written (default: "./Reporting/Guard/images/")')

    parser.add_argument('--input-file',
                       help='Input markdown file containing Mermaid diagram (default: "./Reporting/Guard/system_diagram.md")')
    
    args = parser.parse_args()
    
    # Check if mermaid-cli is installed
    if not check_mermaid_cli():
        print("Error: mermaid-cli (mmdc) is not installed or not in PATH.", file=sys.stderr)
        print("Install it with: npm install -g @mermaid-js/mermaid-cli", file=sys.stderr)
        sys.exit(1)
    
    # Determine input file
    if args.input_file:
        diagram_file = Path(args.input_file).resolve()
    else:
        diagram_file = Path("./Reporting/Guard/system_diagram.md").resolve()
    
    # Resolve output directory
    output_dir = Path(args.output_dir).resolve()
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if diagram file exists
    if not diagram_file.exists():
        print(f"Error: Diagram file not found: {diagram_file}", file=sys.stderr)
        sys.exit(1)
    
    # Extract Mermaid diagram
    print(f"Extracting Mermaid diagram from: {diagram_file}")
    mermaid_content = extract_mermaid_diagram(str(diagram_file))
    
    if not mermaid_content:
        print("Error: No Mermaid diagram found in the file", file=sys.stderr)
        sys.exit(1)
    
    # Generate output filename
    output_file = output_dir / "system_diagram.png"
    
    # Convert to PNG
    print(f"Converting diagram to PNG: {output_file}")
    success = convert_mermaid_to_png(mermaid_content, str(output_file))
    
    if success:
        print(f"Conversion completed successfully!")
        print(f"Output file: {output_file}")
    else:
        print("Conversion failed!", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()