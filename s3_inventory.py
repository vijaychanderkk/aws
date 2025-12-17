import boto3
import csv
from datetime import datetime, timedelta
import sys

def get_last_access_from_cloudtrail(bucket_name, days_back=90):
    """
    Check CloudTrail for last access to bucket
    Note: CloudTrail must be enabled for this to work
    """
    try:
        cloudtrail = boto3.client('cloudtrail')
        
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days_back)
        
        # Look for any events related to this bucket
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'ResourceName', 'AttributeValue': bucket_name}
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=1  # We only need the most recent event
        )
        
        if response['Events']:
            last_event = response['Events'][0]
            event_time = last_event['EventTime']
            event_name = last_event['EventName']
            return {
                'last_access_date': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                'last_event': event_name,
                'days_since_access': (datetime.now(event_time.tzinfo) - event_time).days
            }
        else:
            return {
                'last_access_date': f'No activity in last {days_back} days',
                'last_event': 'None',
                'days_since_access': f'>{days_back}'
            }
    except Exception as e:
        return {
            'last_access_date': f'Error: {str(e)}',
            'last_event': 'Error',
            'days_since_access': 'N/A'
        }

def get_bucket_object_info(bucket_name):
    """
    Alternative method to get bucket size by listing objects
    More accurate but slower for large buckets
    """
    try:
        s3_client = boto3.client('s3')
        
        total_size = 0
        total_objects = 0
        last_modified = None
        
        paginator = s3_client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket_name)
        
        print(f"  Counting objects in {bucket_name}...")
        
        for page in page_iterator:
            if 'Contents' in page:
                for obj in page['Contents']:
                    total_size += obj['Size']
                    total_objects += 1
                    
                    # Track most recent modification
                    if last_modified is None or obj['LastModified'] > last_modified:
                        last_modified = obj['LastModified']
        
        return {
            'size_gb': round(total_size / (1024**3), 4),
            'object_count': total_objects,
            'last_modified': last_modified.strftime('%Y-%m-%d %H:%M:%S') if last_modified else 'Empty bucket'
        }
    except Exception as e:
        print(f"  Error getting object info: {e}")
        return {
            'size_gb': 0,
            'object_count': 0,
            'last_modified': 'Error'
        }

def get_s3_bucket_details(use_cloudwatch=True, check_cloudtrail=True):
    """
    Main function to collect all bucket details
    """
    s3_client = boto3.client('s3')
    
    buckets_data = []
    
    # Get all buckets
    try:
        buckets = s3_client.list_buckets()['Buckets']
        print(f"\nFound {len(buckets)} buckets to analyze\n")
    except Exception as e:
        print(f"Error listing buckets: {e}")
        print("Make sure you have s3:ListAllMyBuckets permission")
        return []
    
    for idx, bucket in enumerate(buckets, 1):
        bucket_name = bucket['Name']
        print(f"[{idx}/{len(buckets)}] Processing: {bucket_name}")
        
        try:
            # Basic bucket info
            bucket_info = {
                'Bucket Name': bucket_name,
                'Creation Date': bucket['CreationDate'].strftime('%Y-%m-%d'),
            }
            
            # Get bucket location
            try:
                location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_info['Region'] = location['LocationConstraint'] or 'us-east-1'
            except Exception as e:
                bucket_info['Region'] = 'Access Denied'
                print(f"  Warning: Cannot get location - {e}")
            
            # Get bucket size and object count
            if use_cloudwatch:
                try:
                    cloudwatch = boto3.client('cloudwatch', region_name=bucket_info['Region'])
                    
                    # Get bucket size
                    size_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/S3',
                        MetricName='BucketSizeBytes',
                        Dimensions=[
                            {'Name': 'BucketName', 'Value': bucket_name},
                            {'Name': 'StorageType', 'Value': 'StandardStorage'}
                        ],
                        StartTime=datetime.now() - timedelta(days=2),
                        EndTime=datetime.now(),
                        Period=86400,
                        Statistics=['Average']
                    )
                    
                    if size_response['Datapoints']:
                        size_bytes = size_response['Datapoints'][0]['Average']
                        bucket_info['Size (GB)'] = round(size_bytes / (1024**3), 4)
                    else:
                        # Fallback to object listing
                        obj_info = get_bucket_object_info(bucket_name)
                        bucket_info['Size (GB)'] = obj_info['size_gb']
                    
                    # Get object count
                    count_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/S3',
                        MetricName='NumberOfObjects',
                        Dimensions=[
                            {'Name': 'BucketName', 'Value': bucket_name},
                            {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
                        ],
                        StartTime=datetime.now() - timedelta(days=2),
                        EndTime=datetime.now(),
                        Period=86400,
                        Statistics=['Average']
                    )
                    
                    if count_response['Datapoints']:
                        bucket_info['Object Count'] = int(count_response['Datapoints'][0]['Average'])
                    else:
                        obj_info = get_bucket_object_info(bucket_name)
                        bucket_info['Object Count'] = obj_info['object_count']
                        
                except Exception as e:
                    print(f"  CloudWatch error, using object listing: {e}")
                    obj_info = get_bucket_object_info(bucket_name)
                    bucket_info['Size (GB)'] = obj_info['size_gb']
                    bucket_info['Object Count'] = obj_info['object_count']
            else:
                # Use object listing method
                obj_info = get_bucket_object_info(bucket_name)
                bucket_info['Size (GB)'] = obj_info['size_gb']
                bucket_info['Object Count'] = obj_info['object_count']
                bucket_info['Last Object Modified'] = obj_info['last_modified']
            
            # Get last access from CloudTrail
            if check_cloudtrail:
                print(f"  Checking CloudTrail for last access...")
                access_info = get_last_access_from_cloudtrail(bucket_name)
                bucket_info['Last Access Date'] = access_info['last_access_date']
                bucket_info['Last Event Type'] = access_info['last_event']
                bucket_info['Days Since Last Access'] = access_info['days_since_access']
            
            # Get bucket tags (to identify owner)
            try:
                tags = s3_client.get_bucket_tagging(Bucket=bucket_name)
                tag_dict = {tag['Key']: tag['Value'] for tag in tags['TagSet']}
                bucket_info['Owner'] = tag_dict.get('Owner', tag_dict.get('owner', 'Not Tagged'))
                bucket_info['Environment'] = tag_dict.get('Environment', tag_dict.get('environment', 'Not Tagged'))
                bucket_info['Project'] = tag_dict.get('Project', tag_dict.get('project', 'Not Tagged'))
                bucket_info['CostCenter'] = tag_dict.get('CostCenter', tag_dict.get('cost-center', 'Not Tagged'))
            except Exception as e:
                bucket_info['Owner'] = 'No Tags'
                bucket_info['Environment'] = 'No Tags'
                bucket_info['Project'] = 'No Tags'
                bucket_info['CostCenter'] = 'No Tags'
            
            # Get versioning status
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                bucket_info['Versioning'] = versioning.get('Status', 'Disabled')
            except:
                bucket_info['Versioning'] = 'Unknown'
            
            # Get lifecycle policies
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                bucket_info['Lifecycle Policy'] = 'Yes'
                bucket_info['Lifecycle Rules Count'] = len(lifecycle['Rules'])
            except:
                bucket_info['Lifecycle Policy'] = 'No'
                bucket_info['Lifecycle Rules Count'] = 0
            
            # Get encryption status
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                bucket_info['Encryption'] = 'Enabled'
            except:
                bucket_info['Encryption'] = 'Disabled'
            
            # Get public access block settings
            try:
                public_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = public_block['PublicAccessBlockConfiguration']
                if all([config.get('BlockPublicAcls'), config.get('BlockPublicPolicy'),
                       config.get('IgnorePublicAcls'), config.get('RestrictPublicBuckets')]):
                    bucket_info['Public Access'] = 'Fully Blocked'
                else:
                    bucket_info['Public Access'] = 'Partially Allowed'
            except:
                bucket_info['Public Access'] = 'Not Configured'
            
            # Calculate estimated monthly cost (rough estimate)
            try:
                size_gb = float(bucket_info['Size (GB)'])
                # Standard storage pricing (~$0.023 per GB/month in us-east-1)
                bucket_info['Est. Monthly Cost ($)'] = round(size_gb * 0.023, 2)
            except:
                bucket_info['Est. Monthly Cost ($)'] = 0
            
            # Add recommendation flag
            days_since = bucket_info.get('Days Since Last Access', 'N/A')
            size_gb = bucket_info.get('Size (GB)', 0)
            
            if isinstance(days_since, int) and days_since > 90 and size_gb > 10:
                bucket_info['Recommendation'] = 'Review for Archival/Deletion'
            elif isinstance(days_since, int) and days_since > 180:
                bucket_info['Recommendation'] = 'Strong Candidate for Deletion'
            elif bucket_info.get('Lifecycle Policy') == 'No' and size_gb > 100:
                bucket_info['Recommendation'] = 'Add Lifecycle Policy'
            else:
                bucket_info['Recommendation'] = 'Keep - Active'
            
            buckets_data.append(bucket_info)
            print(f"  ✓ Completed\n")
            
        except Exception as e:
            print(f"  ✗ Error processing bucket {bucket_name}: {e}\n")
            continue
    
    return buckets_data

def export_to_csv(data, filename='s3_bucket_inventory.csv'):
    """
    Export collected data to CSV file
    """
    if not data:
        print("No data to export")
        return
    
    keys = data[0].keys()
    
    with open(filename, 'w', newline='', encoding='utf-8') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)
    
    print(f"\n{'='*60}")
    print(f"✓ Data exported to: {filename}")
    print(f"{'='*60}")

def print_summary(data):
    """
    Print summary statistics
    """
    if not data:
        return
    
    total_buckets = len(data)
    total_size = sum(float(b.get('Size (GB)', 0)) for b in data)
    total_cost = sum(float(b.get('Est. Monthly Cost ($)', 0)) for b in data)
    
    review_candidates = sum(1 for b in data if 'Review' in b.get('Recommendation', ''))
    delete_candidates = sum(1 for b in data if 'Deletion' in b.get('Recommendation', ''))
    
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Total Buckets: {total_buckets}")
    print(f"Total Storage: {total_size:.2f} GB")
    print(f"Est. Monthly Cost: ${total_cost:.2f}")
    print(f"Review Candidates: {review_candidates}")
    print(f"Deletion Candidates: {delete_candidates}")
    print(f"Potential Monthly Savings: ${sum(float(b.get('Est. Monthly Cost ($)', 0)) for b in data if 'Deletion' in b.get('Recommendation', '')):.2f}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    print("="*60)
    print("AWS S3 Bucket Inventory & Analysis Tool")
    print("="*60)
    
    # Check if user wants to skip CloudTrail (slower)
    check_cloudtrail = True
    if len(sys.argv) > 1 and sys.argv[1] == '--no-cloudtrail':
        check_cloudtrail = False
        print("\nNote: CloudTrail checking disabled (faster but no last access data)")
    
    print("\nStarting S3 bucket inventory...")
    print("This may take several minutes depending on the number of buckets...\n")
    
    # Collect data
    bucket_details = get_s3_bucket_details(
        use_cloudwatch=True,
        check_cloudtrail=check_cloudtrail
    )
    
    if bucket_details:
        # Export to CSV
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f's3_inventory_{timestamp}.csv'
        export_to_csv(bucket_details, filename)
        
        # Print summary
        print_summary(bucket_details)
        
        print(f"Next steps:")
        print(f"1. Open {filename} in Excel/Sheets")
        print(f"2. Sort by 'Recommendation' column")
        print(f"3. Contact bucket owners for review")
        print(f"4. Document decisions and take action")
    else:
        print("\n✗ No data collected. Please check your AWS permissions.")
