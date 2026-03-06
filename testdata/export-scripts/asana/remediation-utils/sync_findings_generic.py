#!/usr/bin/env python3
"""
Generic Asana Finding Sync with Evidence
Works for any AWS finding type (CloudFront, GuardDuty, Inspector, etc.)

Usage:
  python sync_findings_generic.py --csv findings.csv --update-comments --attach-screenshots --mark-complete
"""

import os
import sys
import csv
import subprocess
import requests
import argparse
import urllib3
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont

# Disable SSL warnings for corporate proxy environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add UTF-8 support for Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

PROJECT_GID = '1211710038011414'

def get_asana_token():
    """Get Asana token from environment or 1Password"""
    # Try environment variables first
    token = os.getenv('ASANA_TOKEN') or os.getenv('ASANA_ACCESS_TOKEN')
    if token:
        return token
    
    # Try 1Password CLI
    try:
        result = subprocess.run(
            ['op', 'read', 'op://HAEA/p37-cspm-remediation/credential'],
            capture_output=True, text=True, check=True, timeout=10
        )
        return result.stdout.strip()
    except:
        return None

def find_task_by_name(headers, task_prefix):
    """Find Asana task by name prefix (e.g., 'AWS-013')"""
    response = requests.get(
        f'https://app.asana.com/api/1.0/projects/{PROJECT_GID}/tasks',
        headers=headers,
        params={'opt_fields': 'name,gid'},
        timeout=30,
        verify=False
    )

    if response.status_code == 200:
        for task in response.json()['data']:
            if task['name'].startswith(task_prefix):
                return task['gid']
    return None

def post_comment(headers, task_gid, comment_text):
    """Post comment to Asana task"""
    response = requests.post(
        f'https://app.asana.com/api/1.0/tasks/{task_gid}/stories',
        headers=headers,
        json={'data': {'text': comment_text}},
        timeout=30,
        verify=False
    )
    return response.status_code == 201

def mark_complete_with_status(headers, task_gid, status_value='Closed'):
    """Mark task complete and update Status custom field"""
    # Get custom fields to find Status field GID
    response = requests.get(
        f'https://app.asana.com/api/1.0/tasks/{task_gid}',
        headers=headers,
        params={'opt_fields': 'custom_fields.gid,custom_fields.name,custom_fields.enum_options'},
        timeout=30,
        verify=False
    )

    status_field_data = None
    if response.status_code == 200:
        for field in response.json()['data'].get('custom_fields', []):
            if field['name'] == 'Status':
                for option in field.get('enum_options', []):
                    if option['name'] in [status_value, 'Closed', 'Remediated', 'Complete']:
                        status_field_data = {
                            'field_gid': field['gid'],
                            'option_gid': option['gid']
                        }
                        break

    # Update task
    update_data = {'completed': True}
    if status_field_data:
        update_data['custom_fields'] = {
            status_field_data['field_gid']: status_field_data['option_gid']
        }

    response = requests.put(
        f'https://app.asana.com/api/1.0/tasks/{task_gid}',
        headers=headers,
        json={'data': update_data},
        timeout=30,
        verify=False
    )
    return response.status_code == 200

def run_validation(finding_arn, profile='haea-sso'):
    """Run validation command and return output"""
    # Use Python script on Windows, bash on Linux
    if sys.platform == 'win32':
        cmd = [
            'python', 'utils/findings-utils/scripts/verify-finding-status.py',
            finding_arn, profile
        ]
    else:
        cmd = [
            'bash', 'utils/findings-utils/scripts/verify-finding-status.sh',
            finding_arn, profile
        ]
    
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        print(f"    Validation error: {e}")
        return None

def text_to_image(text, output_path, font_size=14):
    """Convert terminal text to PNG image"""
    try:
        try:
            font = ImageFont.truetype("consola.ttf", font_size)
        except:
            font = ImageFont.load_default()

        lines = text.split('\n')
        max_len = max(len(line) for line in lines) if lines else 80
        char_width = font_size * 0.6
        char_height = font_size * 1.4

        img = Image.new('RGB', (int(max_len * char_width) + 40, int(len(lines) * char_height) + 40), (255, 255, 255))
        draw = ImageDraw.Draw(img)

        y = 20
        for line in lines:
            draw.text((20, y), line, font=font, fill=(0, 0, 0))
            y += char_height

        img.save(output_path, 'PNG')
        return True
    except:
        return False

def upload_screenshot(headers, task_gid, image_path, filename):
    """Upload screenshot to task"""
    if not os.path.exists(image_path):
        return None

    with open(image_path, 'rb') as f:
        files = {'file': (filename, f, 'image/png')}
        response = requests.post(
            f'https://app.asana.com/api/1.0/tasks/{task_gid}/attachments',
            headers=headers, files=files, timeout=30, verify=False
        )

    return response.json()['data']['gid'] if response.status_code == 200 else None

def process_csv_finding(headers, row, args):
    """Process single finding from CSV"""
    task_name = row['Task Name']
    resolution_note = row.get('Resolution Note', '')
    task_prefix = task_name.split('|')[0].strip()

    print(f"  Finding Asana task...")
    task_gid = find_task_by_name(headers, task_prefix)
    if not task_gid:
        print(f"  Task not found: {task_prefix}")
        return False

    print(f"  Found: {task_gid}")

    # Post comment if requested
    if args.update_comments and resolution_note:
        print(f"  Posting comment...")
        post_comment(headers, task_gid, resolution_note)

    # Attach screenshot if requested
    if args.attach_screenshots and 'Finding ID' in row:
        finding_arn = row['Finding ID']
        print(f"  Running validation...")

        output = run_validation(finding_arn, args.profile)
        if output:
            date_str = datetime.now().strftime('%Y%m%d')
            filename = f'{task_prefix}_console_validation_{date_str}.png'
            temp_path = os.path.join(os.environ.get('TEMP', '/tmp'), filename)

            if text_to_image(output, temp_path):
                print(f"  Uploading screenshot...")
                if upload_screenshot(headers, task_gid, temp_path, filename):
                    print(f"    Screenshot uploaded successfully")
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            print(f"    Validation failed - skipping screenshot")

    # Mark complete if requested
    if args.mark_complete:
        print(f"  Marking complete...")
        mark_complete_with_status(headers, task_gid, args.status_value)

    return True

def main():
    parser = argparse.ArgumentParser(description='Generic Asana finding sync')
    parser.add_argument('--csv', required=True, help='CSV file with findings')
    parser.add_argument('--update-comments', action='store_true', help='Post Resolution Note as comment')
    parser.add_argument('--attach-screenshots', action='store_true', help='Attach validation screenshots')
    parser.add_argument('--mark-complete', action='store_true', help='Mark tasks complete')
    parser.add_argument('--status-value', default='Closed', help='Status field value (default: Closed)')
    parser.add_argument('--profile', default='haea-sso', help='AWS profile (default: haea-sso)')

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("Generic Asana Finding Sync")
    print("=" * 70)
    print(f"CSV: {args.csv}")
    print(f"Update comments: {args.update_comments}")
    print(f"Attach screenshots: {args.attach_screenshots}")
    print(f"Mark complete: {args.mark_complete}")
    print("=" * 70 + "\n")

    token = get_asana_token()
    if not token:
        print("Failed to get token")
        return
    headers = {'Authorization': f'Bearer {token}'}

    # Read CSV
    with open(args.csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        findings = list(reader)

    print(f"Processing {len(findings)} findings...\n")

    successful = 0
    for i, row in enumerate(findings, 1):
        task_name = row['Task Name']
        print(f"[{i}/{len(findings)}] {task_name.split('|')[0].strip()}")
        print("-" * 70)

        if process_csv_finding(headers, row, args):
            successful += 1

        print()

    print("=" * 70)
    print(f"Successful: {successful}/{len(findings)}")
    print("=" * 70 + "\n")

if __name__ == '__main__':
    main()
