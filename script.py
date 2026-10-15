import argparse
import os
import sys
import yara


def parse_arguments():
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description="YARA File Scanner - Incident Response Tool"
  )
  parser.add_argument(
      "-d",
      "--directory",
      required=True,
      help="Target directory to scan for threats",
  )
  parser.add_argument(
      "-r",
      "--rules",
      default="rules",
      help="Directory containing YARA rule files (default: 'rules')",
  )
  return parser.parse_args()


def compile_rules(rules_dir):
  """Collects all .yar files from the rules directory and compiles them."""
  filepaths = {}

  if not os.path.exists(rules_dir):
    print(f"[-] Rules directory '{rules_dir}' does not exist!")
    sys.exit(1)

  for filename in os.listdir(rules_dir):
    if filename.endswith(".yar") or filename.endswith(".yara"):
      rule_name = os.path.splitext(filename)[0]
      filepaths[rule_name] = os.path.join(rules_dir, filename)

  if not filepaths:
    print(f"[-] No YARA rule files found in '{rules_dir}'.")
    sys.exit(1)

  print(
      f"[*] Found {len(filepaths)} rule file(s). Compiling YARA rules..."
  )
  try:
    compiled_rules = yara.compile(filepaths=filepaths)
    print("[+] Compilation successful!\n")
    return compiled_rules
  except yara.SyntaxError as e:
    print(f"[-] YARA Syntax Error: {e}")
    sys.exit(1)
  except Exception as e:
    print(f"[-] Failed to compile rules: {e}")
    sys.exit(1)


def scan_target_directory(target_dir, compiled_rules):
  """Recursively scans the target directory using the compiled YARA rules."""
  if not os.path.exists(target_dir):
    print(f"[-] Target directory '{target_dir}' does not exist!")
    sys.exit(1)

  print(f"[*] Starting scan on directory: '{target_dir}'...\n" + "=" * 50)

  scanned_files_count = 0
  infected_files_count = 0

  for root, dirs, files in os.walk(target_dir):
    for file in files:
      file_path = os.path.join(root, file)
      scanned_files_count += 1

      try:
        matches = compiled_rules.match(file_path)
        if matches:
          infected_files_count += 1
          print(f"[!] ALERT: Suspicious file detected -> {file_path}")
          for match in matches:
            print(f"    [>] Triggered Rule: {match.rule}")
            if match.strings:
              # Display matched strings safely
              matched_strs = [
                  s[1].decode("utf-8", errors="ignore") for s in match.strings
              ]
              print(f"    [>] Matched Patterns: {set(matched_strs)}")
          print("-" * 50)
      except Exception:
        # Skip files that cannot be read due to permissions or locks
        pass

  print("=" * 50)
  print("[*] Scan completed.")
  print(f"    - Total files scanned: {scanned_files_count}")
  print(f"    - Suspicious files found: {infected_files_count}")


if __name__ == "__main__":
  args = parse_arguments()

  # Step 1: Compile YARA rules from the specified folder
  rules = compile_rules(args.rules)

  # Step 2: Scan the target directory provided via arguments
  scan_target_directory(args.directory, rules)