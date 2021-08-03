# For all buckets determine if they enforce encryption according to https://aws.amazon.com/blogs/security/how-to-prevent-uploads-of-unencrypted-objects-to-amazon-s3
import sys
import traceback
import boto3
from botocore.exceptions import ClientError

# Access our S3 and IAM
s3 = boto3.client('s3')

# Get all buckets
buckets_dict = s3.list_buckets()

# Loop over all buckets
for bucket in buckets_dict['Buckets']:
    try:
        # Get and reort the name of each bucket
        bucket_name=bucket['Name']
        print ('bucket: %s' % bucket_name)

        # Get the policy to parse to see if it is compliant
        full_policy_dict = s3.get_bucket_policy(Bucket=bucket_name)
        policy_str = full_policy_dict['Policy']

        # Policy is a string and needs to be converted to a dict
        policy_dict = eval(policy_str)

        # Loop over all statements, we need to find 3 specific ones
        statements_found = 0

        statements = policy_dict['Statement']
        for statement in statements:

            # The statement must deny access
            if ('Effect', 'Deny') in statement.items():
                condition = statement['Condition']

                # the there are two possible conditions
                comparitor = list(condition.keys())[0]
                conditional_value = list(condition.values())[0]

                # Meets another criteria of our policy
                if comparitor == 'StringNotEquals':
                    if ('s3:x-amz-server-side-encryption', 'AES256') in conditional_value.items():
                        statements_found += 1
                    elif ('s3:x-amz-server-side-encryption', 'aws:kms') in conditional_value.items():
                        statements_found += 1
                elif comparitor == 'Null':
                    if ('s3:x-amz-server-side-encryption', 'true') in conditional_value.items():
                        statements_found += 1

        # If we found 3 or more of those statements, the criteria are met. The "greater than" part allows for the possibility of duplicated statementts
        if (statements_found >= 3):
            print ('Complies with encrytpion enforcement policy\n')
        else:
            print ('In violation of encryption enforcement policy, insufficient policy statements\n')

        # These statements are included as reference doocumentaton and might be useful of additional checks are included in the future.
        #enc = s3.get_bucket_encryption(Bucket=bucket['Name'])
        #rules = enc['ServerSideEncryptionConfiguration']['Rules']

    except ClientError as e:
        expected = False
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            print('In violation of encryption enforcement policy, no policy applied\n')
            expected = True
        if not expected:
            traceback.print_exc(file=sys.stdout)

