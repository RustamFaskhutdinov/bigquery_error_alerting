import subprocess
import re
from termcolor import colored
from google.cloud import monitoring_v3


def select_mode():
    run_modes = ['initialize', '[WIP] update', '[WIP] delete']
    print(colored("----- Select mode -----", 'black', 'on_light_yellow', attrs=['bold']))
    for i, mode in enumerate(run_modes):
        print(f'[{i}] {mode}')
    mode_id = None
    while not isinstance(mode_id, int) or int(mode_id) not in range(len(run_modes)):
        mode_id = input('Enter mode (should match the ID one of the above). To exit type -1: ')
        try:
            mode_id = int(mode_id)
        except:  # noqa: E722
            mode_id = None
        
        if mode_id == -1:
            return None
    return mode_id

def select_project():
    result = subprocess.run(['gcloud projects list --format="value(projectId)" --filter="NOT projectId ~ ^sys"'], shell=True, capture_output=True, text=True)
    projects_list = result.stdout.strip().split('\n')
    print(colored("\n----- Select project -----", 'black', 'on_light_yellow',  attrs=['bold']))
    for i, project_id in enumerate(projects_list):
        print(f'[{i}] {project_id}')
    project_id = None
    while not isinstance(project_id, int) or int(project_id) not in range(len(projects_list)):
        project_id = input('Enter projectID (should match one of the above. # or projectID). To exit type -1: ')
        try:
            project_id = int(project_id)
        except:  # noqa: E722
            if project_id in projects_list:
                return project_id
            else:
                project_id = None
        if project_id == -1:
            return None
    return projects_list[project_id]




def select_notification_channel_types():
    channel_types = ['email & google space', 'email', 'google space',]
    print(colored("\n----- Select channel type -----", 'black', 'on_light_yellow', attrs=['bold']))
    for i, channel_type in enumerate(channel_types):
        print(f'[{i}] {channel_type}')
    channel_type_id = None
    while not isinstance(channel_type_id, int) or int(channel_type_id) not in range(len(channel_types)):
        channel_type_id = input('Enter channel_type (should match the ID one of the above). To exit type -1: ')
        try:
            channel_type_id = int(channel_type_id)
        except:  # noqa: E722
            channel_type_id = None
        
        if channel_type_id == -1:
            return None
    return channel_types[channel_type_id]


def get_alert_policies(client, project_id):
    project_name = f"projects/{project_id}"
    request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
    return list(client.list_alert_policies(request=request))

def create_channel(client, project_id, channel_type, display_name, labels):
    project_name = f"projects/{project_id}"
    channel = monitoring_v3.NotificationChannel(
        type_=channel_type,
        display_name=display_name,
        labels=labels
    )
    return client.create_notification_channel(name=project_name, notification_channel=channel)

def list_notification_channels(client, project_id):
    project_name = f"projects/{project_id}"
    request = monitoring_v3.ListNotificationChannelsRequest(name=project_name)
    return list(client.list_notification_channels(request=request))


def get_google_space_info(default_name="Viden Alert Space"):
    space_name = input(f"\nEnter Google space name (default: {colored(default_name, attrs=['bold'])}): ").strip()
    if space_name == "-1":
        print("Terminating execution.")
        return None, None
    if not space_name:
        space_name = default_name
    
    space_id = None
    while not space_id:
        space_id_input = input("Enter Google space ID: ").strip()
        if space_id_input == "-1":
            print("Terminating execution.")
            return None, None
        if space_id_input:
            space_id = space_id_input
        else:
            print("Space ID cannot be empty. Please enter a valid space ID.")
    
    return space_name, space_id

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def get_email_addresses():
    email_list = []
    print("\nEnter email addresses (one per line). Enter an empty string to finish or -1 to exit.")
    
    while True:
        email = input("Enter email: ").strip()
        if email == '-1':
            print("Terminating execution.")
            return []
        if email == "":
            if len(email_list) == 0:
                print("You must enter at least one valid email address before exiting.")
                continue
            else:
                break
        if is_valid_email(email):
            email_list.append(email)
        else:
            print(colored(f"'{colored(email, attrs=['bold'])}' is not a valid email address. Please try again.", on_color='on_light_red'))
    
    return list(set(email_list))

def include_looker_studio_errors():
    _ls_flag_values = ['No', 'Yes']
    print(colored("\n----- Include LookerStudio errors -----", 'black', 'on_light_yellow', attrs=['bold']))
    for i, ls_flag in enumerate(_ls_flag_values):
        print(f'[{i}] {ls_flag}')
    ls_flag_id = None
    while not isinstance(ls_flag_id, int) or int(ls_flag_id) not in range(len(_ls_flag_values)):
        ls_flag_id = input('\n If Yes errors from LookerStudio jobs will be included (should match the ID one of the above). To exit type -1: ')
        try:
            ls_flag_id = int(ls_flag_id)
        except:  # noqa: E722
            ls_flag_id = None
        
        if ls_flag_id == -1:
            return None
    return ls_flag_id

def create_notification_channel(client, channel_body, project_id):
  n_channel = monitoring_v3.NotificationChannel(channel_body)
  
  request = monitoring_v3.CreateNotificationChannelRequest(
      name=f'projects/{project_id}',
      notification_channel=n_channel
  )
  try:
    creation_response = client.create_notification_channel(request)
    return creation_response.name
  except Exception as e:
    print(f"{colored('Failed to create notification channel', 'light_red')} {channel_body}.\nError: ", colored(e, attrs=['bold'], on_color='on_red'), "\n")
    return None


def initialize(project_id):
    # Initialize clients
    alert_policy_client = monitoring_v3.AlertPolicyServiceClient()
    channel_client = monitoring_v3.NotificationChannelServiceClient()
    
    # Get alert policies
    policies = get_alert_policies(alert_policy_client, project_id)
    default_policy_name = "BigQuery Error Alert"

    if any(policy.display_name == default_policy_name for policy in policies):
        print(f"{colored(default_policy_name, attrs=['bold'])} found. Terminating...")
        return 1
    
    print(f"{colored(default_policy_name, attrs=['bold'])} not found. Initializing...")

    # PART 1: Fetch existing notification channels and get user inputs
    notification_channels_raw = list_notification_channels(channel_client, project_id)
    notification_channels = [{"type": channel.type_, "name": channel.name, "display_name": channel.display_name, "labels": channel.labels}  for channel in notification_channels_raw]
    
    notification_channel_type = select_notification_channel_types()
    
    if notification_channel_type in ['email & google space', 'email']:
        email_list = get_email_addresses()
        if not email_list:
            return 1
        
    if notification_channel_type in ['email & google space', 'google space']:
        google_space_name, google_space_id = get_google_space_info()
        if not google_space_name or not google_space_id:
            return 1
        
    # PART 2: Process the channels
    all_matched_channels = []
    unmatched_channels = []
    
    if notification_channel_type in ['email & google space', 'email']:
        # Filter the notification channels by matching email addresses
        matched_email_channels = [
            channel for channel in notification_channels
            if channel['type'] == 'email' and channel['labels'].get('email_address') in email_list
        ]
        all_matched_channels.extend(matched_email_channels)
        
        # Add unmatched emails to the list
        for email in email_list:
            if not any(channel['type'] == 'email' and channel['labels'].get('email_address') == email for channel in notification_channels):
                unmatched_channels.append({
                    "type": "email",
                    "display_name": email,
                    "labels": {"email_address": email}
                })
    
    if notification_channel_type in ['email & google space', 'google space']:
        # Find the matched Google Chat space channel
        matched_space_channel = next((channel for channel in notification_channels
            if channel['type'] == "google_chat" and channel['labels'].get('space') == f"spaces/{google_space_id}"), None)
        
        if matched_space_channel:
            all_matched_channels.append(matched_space_channel)
        else:
            unmatched_channels.append({
                "type": "google_chat",
                "display_name": google_space_name,
                "labels": {"space": f"spaces/{google_space_id}"}
            })
    
    # PART 3: Create notification channels
    # Output results
    print(f"{colored('Matched channels', 'green', attrs=['bold'])} (new channels will not be created):")
    channel_ids = []
    for channel in all_matched_channels:
        print(channel)
        channel_ids.append(channel['name'])

    print(f"\n{colored('Unmatched channels', 'red', attrs=['bold'])}. Creating notification channels:")
    for channel in unmatched_channels:
        if channel['type'] == 'email':
            print(f"Channel type: {channel['type']}. Email: {channel['labels'].get('email_address')}")
        elif channel['type'] == 'google_chat':
            print(f"Channel type: {channel['type']}. Space ID: {channel['labels'].get('space')}, Space display name: {channel['display_name']}")
    
    input('Click Enter to continue...')
    for channel in unmatched_channels:
        channel_ids.append(create_notification_channel(channel_client, channel, project_id))

    channel_ids = [channel_id for channel_id in channel_ids if channel_id is not None]

    input('Click Enter to continue...')

    # PART 4: Create alert policy

    # Define filters
    include_looker_studio_errors_filter = 'severity="ERROR" AND resource.type="bigquery_resource" AND NOT protoPayload.serviceData.jobCompletedEvent.job.jobName.jobId:"bqux" AND protoPayload.methodName="jobservice.jobcompleted"'
    exclude_looker_studio_errors_filter = 'severity="ERROR" AND resource.type="bigquery_resource" AND NOT protoPayload.serviceData.jobCompletedEvent.job.jobName.jobId:"bqux" AND protoPayload.methodName="jobservice.jobcompleted" AND NOT protoPayload.serviceData.jobCompletedEvent.job.jobConfiguration.labels.requestor="looker_studio"'            

    alert_policy_body = {
        "display_name": default_policy_name,
        "documentation": {
            "content": f"""# {default_policy_name}

Monitors BigQuery for errors and sends notifications.

## Conditions
- **Severity**: ERROR
- **Resource**: BigQuery
- **Exclude**: Job IDs containing "bqux"

## Labels
- **Principal Email**
- **Resource Name**
- **Service Account**
- **Caller IP**
- **Error Message**

## Notifications
- **Email**: Specified addresses
- **Google Chat**: Specified space

## Strategy
- **Auto-Close**: 1 hour
- **Rate Limit**: 10 minutes
""",
        "mime_type": "text/markdown"
    },
    "combiner": "OR",
    "conditions": [
        {
            "condition_matched_log": {
                "filter": exclude_looker_studio_errors_filter,
                "label_extractors": {
                    "PrincipalEmail": 'REGEXP_EXTRACT(protoPayload.authenticationInfo.principalEmail, "(.*)")',
                    "ResourceName": 'REGEXP_EXTRACT(protoPayload.resourceName, "jobs/(.+)")',
                    "ServiceAccountDelegationInfo": 'REGEXP_EXTRACT(protoPayload.authenticationInfo.serviceAccountDelegationInfo.firstPartyPrincipal.principalEmail, "(.*)")',
                    "callerIp": 'REGEXP_EXTRACT(protoPayload.requestMetadata.callerIp, "(.*)")',
                    "errorMessage": 'REGEXP_EXTRACT(protoPayload.status.message, "(.*)")'
                }
            },
            "display_name": "Log match condition"
        }
    ],
    "severity": "WARNING",
    "alert_strategy": {
        "auto_close": "3600s",
        "notification_rate_limit": {
            "period": "600s"
        }
    }
    }
    
    ls_flag_id = include_looker_studio_errors()

    if ls_flag_id == 1:
        alert_policy_body['conditions'][0]['condition_matched_log']['filter'] = include_looker_studio_errors_filter
    elif ls_flag_id is None:
        return 1

    alert_policy = monitoring_v3.AlertPolicy(alert_policy_body)
    alert_policy.notification_channels = channel_ids
    alert_policy_request = monitoring_v3.CreateAlertPolicyRequest(
        name=f"projects/{project_id}",
        alert_policy=alert_policy
    )
    policy_details = alert_policy_client.create_alert_policy(request=alert_policy_request)

    print(f"Policy URL: https://console.cloud.google.com/monitoring/alerting/policies/{policy_details.name.split('/')[-1]}?project={project_id}")
    
    return 0


def main():
    
    mode = select_mode()
    if mode is None:
        return
    
    if mode == 0:
        project_id = select_project()
        if project_id is None:
            return
        status = initialize(project_id)
        if status == 0:
            print("Policy created successfully.")
        else:
            print("Policy creation failed.")
    elif mode == 1:
        print("Update mode is not implemented yet.")
    elif mode == 2:
        print("Delete mode is not implemented yet.")


if __name__ == '__main__':
    main()