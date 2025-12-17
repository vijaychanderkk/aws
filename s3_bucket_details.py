import boto3
import csv
from datetime import datetime, timedelta
from collections import defaultdict
import os

# ====== SSO PROFILE CONFIGURATION ======
AWS_PROFILE = 'PUT-YOUR-PROFILE-NAME-HERE'  # <-- CHANGE THIS
print(f"Using AWS Profile: {AWS_PROFILE}")
# ========================================

def format_size(size_bytes):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def get_folder_structure(bucket_name, session):
    """
    Get complete folder structure with sizes and counts
    """
    s3_client = session.client('s3')
    
    # Dictionary to store folder statistics
    folder_stats = defaultdict(lambda: {
        'size': 0,
        'count': 0,
        'last_modified': None,
        'objects': []
    })
    
    print(f"\nAnalyzing bucket: {bucket_name}")
    print("This may take a while for large buckets...\n")
    
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket_name)
        
        total_objects = 0
        
        for page in page_iterator:
            if 'Contents' not in page:
                continue
                
            for obj in page['Contents']:
                total_objects += 1
                
                if total_objects % 1000 == 0:
                    print(f"  Processed {total_objects} objects...")
                
                key = obj['Key']
                size = obj['Size']
                last_modified = obj['LastModified']
                storage_class = obj.get('StorageClass', 'STANDARD')
                
                # Get object metadata (owner info if available)
                owner = obj.get('Owner', {}).get('DisplayName', 'Unknown')
                
                # Store object details
                object_info = {
                    'key': key,
                    'size': size,
                    'size_formatted': format_size(size),
                    'last_modified': last_modified,
                    'storage_class': storage_class,
                    'owner': owner
                }
                
                # Root level
                folder_stats['ROOT']['size'] += size
                folder_stats['ROOT']['count'] += 1
                folder_stats['ROOT']['objects'].append(object_info)
                
                if folder_stats['ROOT']['last_modified'] is None or last_modified > folder_stats['ROOT']['last_modified']:
                    folder_stats['ROOT']['last_modified'] = last_modified
                
                # Parse folder hierarchy
                if '/' in key:
                    parts = key.split('/')
                    current_path = ''
                    
                    # Process each level of the folder structure
                    for i, part in enumerate(parts[:-1]):  # Exclude the filename
                        if i == 0:
                            current_path = part
                        else:
                            current_path += '/' + part
                        
                        folder_stats[current_path]['size'] += size
                        folder_stats[current_path]['count'] += 1
                        
                        # Only add object to deepest folder
                        if i == len(parts) - 2:
                            folder_stats[current_path]['objects'].append(object_info)
                        
                        if folder_stats[current_path]['last_modified'] is None or last_modified > folder_stats[current_path]['last_modified']:
                            folder_stats[current_path]['last_modified'] = last_modified
        
        print(f"✓ Total objects processed: {total_objects}\n")
        return folder_stats
        
    except Exception as e:
        print(f"✗ Error analyzing bucket: {e}")
        return None

def get_bucket_access_logs(bucket_name, session, days_back=90):
    """
    Check CloudTrail for bucket access patterns
    """
    print(f"Checking CloudTrail for access patterns (last {days_back} days)...")
    
    try:
        cloudtrail = session.client('cloudtrail')
        
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days_back)
        
        # Get all events for this bucket
        events = []
        next_token = None
        
        while True:
            params = {
                'LookupAttributes': [
                    {'AttributeKey': 'ResourceName', 'AttributeValue': bucket_name}
                ],
                'StartTime': start_time,
                'EndTime': end_time,
                'MaxResults': 50
            }
            
            if next_token:
                params['NextToken'] = next_token
            
            response = cloudtrail.lookup_events(**params)
            
            for event in response.get('Events', []):
                events.append({
                    'time': event['EventTime'],
                    'event_name': event['EventName'],
                    'user': event.get('Username', 'Unknown'),
                    'source_ip': event.get('CloudTrailEvent', {})
                })
            
            next_token = response.get('NextToken')
            if not next_token:
                break
        
        # Analyze access patterns
        access_summary = defaultdict(lambda: {'count': 0, 'last_access': None})
        
        for event in events:
            user = event['user']
            access_summary[user]['count'] += 1
            
            if access_summary[user]['last_access'] is None or event['time'] > access_summary[user]['last_access']:
                access_summary[user]['last_access'] = event['time']
        
        print(f"✓ Found {len(events)} access events from {len(access_summary)} users\n")
        return access_summary
        
    except Exception as e:
        print(f"⚠ CloudTrail access: {e}\n")
        return {}

def get_bucket_metadata(bucket_name, session):
    """
    Get bucket-level metadata
    """
    s3_client = session.client('s3')
    
    metadata = {
        'bucket_name': bucket_name
    }
    
    print(f"Getting bucket metadata...")
    
    # Creation date
    try:
        buckets = s3_client.list_buckets()['Buckets']
        for bucket in buckets:
            if bucket['Name'] == bucket_name:
                metadata['creation_date'] = bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S')
                break
    except Exception as e:
        metadata['creation_date'] = f'Error: {e}'
    
    # Region
    try:
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        metadata['region'] = location['LocationConstraint'] or 'us-east-1'
    except Exception as e:
        metadata['region'] = f'Error: {e}'
    
    # Tags
    try:
        tags = s3_client.get_bucket_tagging(Bucket=bucket_name)
        metadata['tags'] = {tag['Key']: tag['Value'] for tag in tags['TagSet']}
    except:
        metadata['tags'] = {}
    
    # Versioning
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        metadata['versioning'] = versioning.get('Status', 'Disabled')
    except:
        metadata['versioning'] = 'Unknown'
    
    # Encryption
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        metadata['encryption'] = 'Enabled'
    except:
        metadata['encryption'] = 'Disabled'
    
    # Lifecycle policy
    try:
        lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        metadata['lifecycle_rules'] = len(lifecycle['Rules'])
    except:
        metadata['lifecycle_rules'] = 0
    
    # Logging
    try:
        logging = s3_client.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' in logging:
            metadata['logging'] = 'Enabled'
            metadata['log_bucket'] = logging['LoggingEnabled'].get('TargetBucket', 'Unknown')
        else:
            metadata['logging'] = 'Disabled'
    except:
        metadata['logging'] = 'Unknown'
    
    # Public access block
    try:
        public_block = s3_client.get_public_access_block(Bucket=bucket_name)
        config = public_block['PublicAccessBlockConfiguration']
        metadata['public_access_blocked'] = all([
            config.get('BlockPublicAcls'),
            config.get('BlockPublicPolicy'),
            config.get('IgnorePublicAcls'),
            config.get('RestrictPublicBuckets')
        ])
    except:
        metadata['public_access_blocked'] = 'Unknown'
    
    print(f"✓ Bucket metadata retrieved\n")
    return metadata

def export_folder_structure_to_csv(folder_stats, filename):
    """
    Export folder structure to CSV
    """
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Folder Path',
            'Level',
            'Object Count',
            'Total Size (Bytes)',
            'Total Size (Formatted)',
            'Last Modified',
            'Average Object Size'
        ])
        
        # Sort folders by path
        sorted_folders = sorted(folder_stats.items())
        
        for folder_path, stats in sorted_folders:
            level = folder_path.count('/') if folder_path != 'ROOT' else 0
            avg_size = stats['size'] / stats['count'] if stats['count'] > 0 else 0
            
            writer.writerow([
                folder_path,
                level,
                stats['count'],
                stats['size'],
                format_size(stats['size']),
                stats['last_modified'].strftime('%Y-%m-%d %H:%M:%S') if stats['last_modified'] else 'N/A',
                format_size(avg_size)
            ])
    
    print(f"✓ Folder structure exported to: {filename}")

def export_all_objects_to_csv(folder_stats, filename):
    """
    Export all objects with full details to CSV
    """
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Object Key',
            'Parent Folder',
            'Size (Bytes)',
            'Size (Formatted)',
            'Last Modified',
            'Storage Class',
            'Owner'
        ])
        
        # Collect all objects from all folders
        all_objects = []
        
        for folder_path, stats in folder_stats.items():
            for obj in stats['objects']:
                # Determine parent folder
                key = obj['key']
                if '/' in key:
                    parent = '/'.join(key.split('/')[:-1])
                else:
                    parent = 'ROOT'
                
                all_objects.append([
                    obj['key'],
                    parent,
                    obj['size'],
                    obj['size_formatted'],
                    obj['last_modified'].strftime('%Y-%m-%d %H:%M:%S'),
                    obj['storage_class'],
                    obj['owner']
                ])
        
        # Sort by key
        all_objects.sort(key=lambda x: x[0])
        
        # Write all objects
        for obj in all_objects:
            writer.writerow(obj)
    
    print(f"✓ All objects exported to: {filename}")

def export_access_logs_to_csv(access_summary, filename):
    """
    Export access logs to CSV
    """
    if not access_summary:
        print("⚠ No access logs to export")
        return
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'User/Principal',
            'Access Count',
            'Last Access',
            'Days Since Last Access'
        ])
        
        # Sort by access count (descending)
        sorted_users = sorted(
            access_summary.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )
        
        for user, stats in sorted_users:
            days_since = (datetime.now(stats['last_access'].tzinfo) - stats['last_access']).days
            
            writer.writerow([
                user,
                stats['count'],
                stats['last_access'].strftime('%Y-%m-%d %H:%M:%S'),
                days_since
            ])
    
    print(f"✓ Access logs exported to: {filename}")

def export_bucket_metadata_to_csv(metadata, filename):
    """
    Export bucket metadata to CSV
    """
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Property', 'Value'])
        
        for key, value in metadata.items():
            if key == 'tags':
                for tag_key, tag_value in value.items():
                    writer.writerow([f'Tag: {tag_key}', tag_value])
            else:
                writer.writerow([key.replace('_', ' ').title(), value])
    
    print(f"✓ Bucket metadata exported to: {filename}")

def print_summary(folder_stats, metadata, access_summary):
    """
    Print summary to console
    """
    print("\n" + "="*70)
    print("BUCKET ANALYSIS SUMMARY")
    print("="*70)
    
    # Bucket info
    print(f"\nBucket: {metadata['bucket_name']}")
    print(f"Region: {metadata['region']}")
    print(f"Created: {metadata.get('creation_date', 'Unknown')}")
    print(f"Versioning: {metadata.get('versioning', 'Unknown')}")
    print(f"Encryption: {metadata.get('encryption', 'Unknown')}")
    print(f"Lifecycle Rules: {metadata.get('lifecycle_rules', 0)}")
    
    # Tags
    if metadata.get('tags'):
        print(f"\nTags:")
        for key, value in metadata['tags'].items():
            print(f"  {key}: {value}")
    
    # Storage summary
    if folder_stats and 'ROOT' in folder_stats:
        root_stats = folder_stats['ROOT']
        print(f"\nStorage Summary:")
        print(f"  Total Objects: {root_stats['count']:,}")
        print(f"  Total Size: {format_size(root_stats['size'])}")
        print(f"  Average Object Size: {format_size(root_stats['size'] / root_stats['count'] if root_stats['count'] > 0 else 0)}")
        
        if root_stats['last_modified']:
            days_since = (datetime.now(root_stats['last_modified'].tzinfo) - root_stats['last_modified']).days
            print(f"  Last Modified: {root_stats['last_modified'].strftime('%Y-%m-%d %H:%M:%S')} ({days_since} days ago)")
    
    # Folder breakdown
    if folder_stats:
        print(f"\nTop 10 Folders by Size:")
        sorted_folders = sorted(
            [(k, v) for k, v in folder_stats.items() if k != 'ROOT'],
            key=lambda x: x[1]['size'],
            reverse=True
        )[:10]
        
        for folder, stats in sorted_folders:
            print(f"  {folder}: {format_size(stats['size'])} ({stats['count']:,} objects)")
    
    # Access summary
    if access_summary:
        print(f"\nAccess Summary (Last 90 days):")
        print(f"  Unique Users: {len(access_summary)}")
        print(f"\nTop 5 Users by Access Count:")
        
        sorted_users = sorted(
            access_summary.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:5]
        
        for user, stats in sorted_users:
            days_since = (datetime.now(stats['last_access'].tzinfo) - stats['last_access']).days
            print(f"  {user}: {stats['count']} accesses (last: {days_since} days ago)")
    
    print("\n" + "="*70)

def analyze_bucket(bucket_name, check_cloudtrail=True):
    """
    Main function to analyze a specific bucket
    """
    # Create session with profile
    session = boto3.Session(profile_name=AWS_PROFILE)
    
    print("="*70)
    print(f"AWS S3 BUCKET DETAILED ANALYSIS")
    print("="*70)
    
    # Get bucket metadata
    metadata = get_bucket_metadata(bucket_name, session)
    
    # Get folder structure
    folder_stats = get_folder_structure(bucket_name, session)
    
    if not folder_stats:
        print("✗ Failed to analyze bucket structure")
        return
    
    # Get access logs (optional - can be slow)
    access_summary = {}
    if check_cloudtrail:
        access_summary = get_bucket_access_logs(bucket_name, session)
    
    # Create timestamp for filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    bucket_safe_name = bucket_name.replace('/', '_').replace('\\', '_')
    
    # Export data
    print("\nExporting data to CSV files...")
    export_bucket_metadata_to_csv(
        metadata,
        f'{bucket_safe_name}_metadata_{timestamp}.csv'
    )
    export_folder_structure_to_csv(
        folder_stats,
        f'{bucket_safe_name}_folders_{timestamp}.csv'
    )
    export_all_objects_to_csv(
        folder_stats,
        f'{bucket_safe_name}_all_objects_{timestamp}.csv'
    )
    
    if access_summary:
        export_access_logs_to_csv(
            access_summary,
            f'{bucket_safe_name}_access_logs_{timestamp}.csv'
        )
    
    # Print summary
    print_summary(folder_stats, metadata, access_summary)
    
    print("\n✓ Analysis complete!")
    print(f"\nGenerated files:")
    print(f"  1. {bucket_safe_name}_metadata_{timestamp}.csv - Bucket configuration")
    print(f"  2. {bucket_safe_name}_folders_{timestamp}.csv - Folder hierarchy")
    print(f"  3. {bucket_safe_name}_all_objects_{timestamp}.csv - All objects with details")
    if access_summary:
        print(f"  4. {bucket_safe_name}_access_logs_{timestamp}.csv - Access patterns")

if __name__ == "__main__":
    import sys
    
    print("="*70)
    print("AWS S3 Bucket Detailed Analysis Tool")
    print("="*70)
    print(f"Using Profile: {AWS_PROFILE}\n")
    
    # Get bucket name from command line or prompt user
    if len(sys.argv) > 1:
        bucket_name = sys.argv[1]
    else:
        bucket_name = input("Enter the S3 bucket name to analyze: ").strip()
    
    if not bucket_name:
        print("✗ Error: No bucket name provided")
        sys.exit(1)
    
    # Check if user wants to skip CloudTrail
    check_cloudtrail = True
    if len(sys.argv) > 2 and sys.argv[2] == '--no-cloudtrail':
        check_cloudtrail = False
        print("Note: CloudTrail checking disabled\n")
    
    # Make sure user is logged in
    print("Make sure you're logged in with: aws sso login --profile", AWS_PROFILE)
    input("Press Enter to continue...")
    
    # Run analysis
    analyze_bucket(bucket_name, check_cloudtrail)
