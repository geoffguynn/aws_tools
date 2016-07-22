#!/usr/bin/python

''' Begin ---- Script Setup Operations ---- '''
#Script Module(s)
import boto3, json, csv, sys, os, base64, uuid, time, inspect, traceback

#Script Author Information
script_info = {
    "name": "AWS_Tools",
    "date": "17 Jul 2016",
    "author": "Geoffrey Guynn",
    "author_email": bytes.decode(base64.b64decode('Z2VvZmZyZXlAZ3V5bm4ub3Jn')),
    "version": "1.0.0.0",
    "copyright": "Copyright 2016 - Geoffrey Guynn - Free use with attribution AS-IS with no Warranty or Liability"
}

#Script Information
script_directory = os.path.dirname(os.path.realpath(__file__))
aws_root = os.path.abspath(os.path.join(script_directory, os.pardir))
json_path = "{aws_root}\\data\\profiles\\AWS_Ubuntu_Free_Tier.json".format(aws_root=aws_root)
session_token = str(uuid.uuid4())
key_store = ""

#Script Developer Options
verbose_logging = True
log_file = "{script_directory}\\logs\\{time_stamp}_AWS_Tools.log".format(script_directory=script_directory, time_stamp=time.strftime('%Y_%m_%dT%H%M%S'))

#Accept a profile path from commandline.
if __name__ == '__main__':
    if len (sys.argv) > 1:
        json_path = sys.argv[1]

''' End ---- Script Setup Operations ---- '''

def log(message=None, source=None, type="Info", exception=None, trace=None, log_file=log_file, throw=None, no_header=False, no_new_line=False, verbose=False):
    #Requires sys, os, time, inspect, traceback modules
    #Determine the calling function's name for logging.
    if not source:
        source = inspect.currentframe().f_back.f_code.co_name
    
    #Logfile prep
    if log_file:
        log_file_directory = os.path.abspath(os.path.join(log_file, os.pardir))
        if not os.path.exists(log_file_directory):
            os.makedirs(log_file_directory)
        
    #Timestamp our log entries.
    date_time_stamp = time.strftime("%m/%d/%y %I:%M:%S%p")
    time_stamp = time.strftime("%I:%M:%S%p")  

    #Process exceptions first
    if exception:
        if log_file:
            with open(log_file, 'a') as f:
                f.write("{time_stamp} [Exception][{source}] {message}\n{trace}\n\n".format(time_stamp=time_stamp, source=source, message=str(exception), trace=trace))
            
        raise Exception("{time_stamp} [Exception][{source}] {message}\n{trace}\n\n".format(time_stamp=time_stamp, source=source, message=str(exception), trace=trace))
    if throw:
        if log_file:
            with open(log_file, 'a') as f:
                f.write("{time_stamp} [Exception][{source}] {message}\n".format(time_stamp=time_stamp, source=source, message=throw))

        raise Exception("{time_stamp} [Exception][{source}] {message}\n".format(time_stamp=time_stamp, source=source, message=throw))

    #Process function messages and verbose messages
    if type.upper() == "function".upper() or verbose == True:
        type = "verbose" if verbose == True else type
        if log_file: #Even if verbose isn't enabled in console, still log verbose messages to the file.
            with open(log_file, 'a') as f:
                f.write("{time_stamp} [{type}][{source}] {message}\n".format(time_stamp=time_stamp, type=type.title(), source=source, message=message))
        if verbose_logging == True:
            print("{time_stamp} [{type}][{source}] {message}".format(time_stamp=time_stamp, type=type.title(), source=source, message=message))
    #Process normal messages
    else:
        #No colors (yet?) :(
        #Message needs headers
        if not no_header:
            if no_new_line:
                if log_file:
                    with open(log_file, 'a') as f:
                        f.write("{time_stamp} [{type}][{source}] {message}".format(time_stamp=time_stamp, type=type.title(), source=source, message=message))
                print("{time_stamp} [{type}][{source}] {message}".format(time_stamp=time_stamp, type=type.title(), source=source, message=message), end="")
            else:
                if log_file:
                    with open(log_file, 'a') as f:
                        f.write("{time_stamp} [{type}][{source}] {message}\n".format(time_stamp=time_stamp, type=type.title(), source=source, message=message))
                print("{time_stamp} [{type}][{source}] {message}".format(time_stamp=time_stamp, type=type.title(), source=source, message=message))
        #Message uses no headers.
        else: 
            if no_new_line:
                if log_file:
                    with open(log_file, 'a') as f:
                        f.write("{message}".format(message=message))
                print("{message}".format(message=message.capitalize()), end="")
            else:
                if log_file:
                    with open(log_file, 'a') as f:
                        f.write("{message}\n".format(message=message))
                print("{message}".format(message=message.capitalize()))


def get_json_profile(path):
    if not path:
        log(throw="No profile was provided, this script requires a JSON profile to perform AWS actions.")

    if not os.path.isfile(path):
        log(throw="Profile JSON {path} doesn't exist!".format(path=path))
    else:
        log(message="Reading JSON profile from {path}".format(path=path))
        with open( path, 'r' ) as json_file:
            json_data = json.load(json_file)

    log(type="Function",message="Finished execution")
    return json_data


def get_aws_local_credentials(username=None, access_key=None, secret_key=None, credential_file=None):
    #The user hardcoded credentials, use them.
    if access_key and secret_key:
        log(message="Using hardcoded credentials.")
        log(verbose=True,message="return {'username': {username}; 'access_key': ********; 'secret_key': ********}".format(username=username))
        return {'username': username, 'access_key': access_key, 'secret_key': secret_key}

    #No hardcoded credentials, did they provide a downloaded credentials CSV from AWS?
    if not credential_file:
        log(throw="No AWS access_key/secret_key combo specified and no AWS credential file specified, you must provide one or the other!")

    #Does that CSV exist?
    if not os.path.isfile(credential_file):
        raise Exception( "Credential file {credential_file} doesn't exist!".format(credential_file=credential_file, ) )

    #Read the CSV and look for a matching username. Skip headers if it has any.
    with open( credential_file, 'r' ) as fs:
        reader = csv.reader(fs)

        if csv.Sniffer.has_header:
            next(reader, None)

        credentials = []
        
        for row in reader:
            if username.upper() == row[0].upper():
                return {'username': row[0], 'access_key': row[1], 'secret_key': row[2]}

        raise Exception( "No credentials found for {username} in {credential_file}".format(username=username, credential_file=credential_file) )


def get_aws_session(connection):
    current_function = inspect.currentframe().f_code.co_name
    
    if connection['use_default_profile'] == True:
        return boto3.session.Session( region_name=connection['region_name'] )

    else:
        credentials = get_aws_local_credentials(
            username=connection['username'],
            access_key=connection['access_key'],
            secret_key=connection['secret_key'],
            credential_file=connection['credential_file'] )
        
        return boto3.session.Session(
            region_name=connection['region_name'],
            aws_access_key_id=credentials.get('access_key'),
            aws_secret_access_key=credentials.get('secret_key') )


def new_aws_keypair(key_name,client,path=key_store):
    if not path:
        log(throw="Unable to create new keypair {key_name}, no file specified to save the private key!".format(key_name=key_name) )
    
    try:
        key_pair = client.create_key_pair(KeyName=key_name)
        log(message="New KeyPair created Name={key_name} Fingerprint={fingerprint}".format(key_name=key_name, fingerprint=key_pair['KeyFingerprint']))
        if not os.path.exists(path):
            os.makedirs(path)
        path = "{path}\{key_name}.pem".format(path=path,key_name=key_name)
        with open(path, 'w') as fs:
            fs.write(key_pair['KeyMaterial'])
        log(message="Private key saved to {path}".format(path=path))

    except Exception as e:
        log(exception=e,trace=traceback.format_exc())
    
    return key_pair


def new_ec2_instance(client, instances):
    reservations = []

    for instance in instances:
        log(message="Creating instance {instance_name}".format(instance_name=instance['name']))
        
        #Check to see if we are going to create a KeyPair
        if instance['create_key'] == True:
            if instance['key_store']:
                key_pair = new_aws_keypair(
                    client=client,
                    path=instance['key_store'],
                    key_name="{instance_name}_{session_token}".format(instance_name=instance['name'],session_token=session_token))
            else:
                key_pair = new_aws_keypair(
                    client=client,
                    key_name="{instance_name}_{session_token}".format(instance_name=instance['name'],session_token=session_token))
            
            instance['config']['KeyName'] = key_pair['KeyName']

        if not instance['config']['KeyName']:
            log(type="warning",message="This instance doesn't have a KeyPair! You will be unable to connect unless the base image comes preloaded with another connection method!")
        try:
            #Remove null/empty JSON entries.
            config_kwargs=dict((k, v) for k, v in instance['config'].items() if v)

            #Pass a param dict into the method with keyword arguments that have a value.
            reservations += client.run_instances(**config_kwargs)

            log(type="Success",message="Successfully created instance {instance_name}".format(instance_name=instance['name']))
        except Exception as e:
            log(exception=e,trace=traceback.format_exc())

    return reservations


#Main Execution

#Read the JSON profile data.
aws_profile = get_json_profile(json_path)

#Create an AWS session and client with settings from JSON profile
aws_session = get_aws_session( aws_profile['connection'] )
ec2_client = aws_session.client('ec2')

#Create any instances in the JSON profile.
reservations = new_ec2_instance( client=ec2_client, instances=aws_profile['instances'] )
