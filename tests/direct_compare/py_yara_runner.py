#!/usr/bin/env python3
import sys
import json
import argparse
import yara


def parse_args():
    """Parse command line arguments matching node_yara_runner.js structure."""
    parser = argparse.ArgumentParser(description='Run YARA rules using Python yara library')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--rule', type=str, help='YARA rule text')
    group.add_argument('--rulefile', type=str, help='Path to YARA rule file')
    parser.add_argument('--file', type=str, required=True, help='Path to file to scan')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    
    return parser.parse_args()


def format_match_results(matches, file_data):
    """
    Format YARA match results to match node_yara_runner.js output structure.
    
    Args:
        matches: List of yara.Match objects
        file_data: The scanned file data
    
    Returns:
        dict: Formatted results matching the expected JSON structure
    """
    results = []
    
    for match in matches:
        # Build strings dictionary
        strings_dict = {}
        
        # Get all string identifiers from the rule
        for string in match.strings:
            identifier = string.identifier
            instances = string.instances
            
            if identifier not in strings_dict:
                strings_dict[identifier] = {
                    "identifier": identifier,
                    "matched": len(instances) > 0,
                    "count": len(instances),
                    "matches": [],
                    "offsets": [],
                    "length": None
                }
            
            # Add match instances
            for instance in instances:
                offset = instance.offset
                matched_data = instance.matched_data
                length = len(matched_data)
                
                # Check if it's a wide string (UTF-16LE encoding check)
                # Wide strings have null bytes between characters
                is_wide = False
                if length > 1 and all(matched_data[i] == 0 for i in range(1, length, 2)):
                    is_wide = True
                
                match_info = {
                    "offset": offset,
                    "length": length
                }
                
                # Only add isWide field for literal strings (not regex/hex)
                if identifier.startswith('$') and not any(c in identifier for c in ['regex', 'hex']):
                    # Check if the string definition likely has ascii/wide modifiers
                    match_info["isWide"] = is_wide
                
                strings_dict[identifier]["matches"].append(match_info)
                strings_dict[identifier]["offsets"].append(offset)
                
                # Set length (use first match's length)
                if strings_dict[identifier]["length"] is None:
                    strings_dict[identifier]["length"] = length
        
        # Add any strings that didn't match
        # Note: Python yara doesn't easily expose non-matching strings,
        # so we'll only include strings that matched
        
        result = {
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": list(match.tags),
            "metadata": dict(match.meta),
            "strings": strings_dict
        }
        
        results.append(result)
    
    return {"matches": results}


def main():
    """Main function to run YARA scanner."""
    args = parse_args()
    
    try:
        # Load YARA rules
        if args.rulefile:
            rules = yara.compile(filepath=args.rulefile)
        else:
            rules = yara.compile(source=args.rule)
        
        # Read file to scan
        with open(args.file, 'rb') as f:
            file_data = f.read()
        
        # Run scan
        matches = rules.match(data=file_data)
        
        # Format output
        if args.json:
            result = format_match_results(matches, file_data)
            print(json.dumps(result, indent=2))
        else:
            # Simple MATCH/NO MATCH output
            if matches:
                print("MATCH")
            else:
                print("NO MATCH")
    
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
