from boto3.session import Session

class Cleaner:
    def __init__(self, config):
        self.config = config
        self.session = Session(aws_access_key_id=config['aws_access_key_id'],
                            aws_secret_access_key=config['aws_secret_access_key'],
                            region_name=config['region_name'])
                            
    def clean_all(self):
        #self.clean_ec2()
        self.clean_iam()
        return True
        
    def clean_ec2(self):
        print('START ec2 clean')
        ec2 = self.session.resource('ec2')
        for instance in ec2.instances.all():
            print(instance.id)
            instance.terminate(DryRun=False)
        print('END ec2 clean')
        return True
        
    def clean_iam(self):
        print('START iam clean')
        client = self.session.client('iam')
        iam = self.session.resource('iam')
        for user in iam.users.all():
            print(user)
            if self.config['protected_users'].count(user.name) > 0:
                print('Skipping protected user: ' + user.name)
                continue
            self.delete_user(user)
        print('END iam clean')
        return True
    
    def delete_user(self, user):
        #remove groups
        for group in user.groups.all():
           user.remove_group(GroupName=group.name)
        #remove keys
        for access_key in user.access_keys.all():
            access_key.delete()
        #remove signing certs
        for signing_certificate in user.signing_certificates.all():
            signing_certificate.delete()
        #remove inline policies
        for policy in user.policies.all():
            policy.delete()
        #remove attached policies
        for policy in user.attached_policies.all():
            user.detach_policy(PolicyArn=policy.arn)
        #finally delete user
        user.delete()
        return True