import pandas as pd
import os
import requests
import sys

# get entity ID from global search by Image Name
def get_entity_id(image_name, auth_header):
    payload = {"filter": {"freeTextPhrase": image_name}}
    url = "https://api.eu1.dome9.com/v2/protected-asset/search"
    response = requests.post(url, json=payload, headers=auth_header)

    if response.status_code == 201:
        assets = response.json().get('assets', [])
        for asset in assets:
            if asset.get("name") == image_name:
                entity_id = asset.get("entityId")
                if entity_id.startswith('sha256:'):
                    return entity_id[7:]  # Strip 'sha256:'
                return entity_id
        print(f"No entity found for image name: {image_name}")
    else:
        print(f"Error retrieving entity ID: {response.status_code} - {response.text}")
    return None

# Define List of CVEs and split to avoid too long lines in the exclusion list
def chunk_cve_list(cve_list, size=15):
    """Yield successive size chunks from cve_list."""
    for i in range(0, len(cve_list), size):
        yield cve_list[i:i + size]

# Retrieve parameters from environment variables sent from Jenkins
search_name = os.getenv('CVE_LIST_NAME')
image_name_to_search = os.getenv('IMAGE_NAME')
auth_token = os.getenv('AUTH_TOKEN')

if not all([search_name, image_name_to_search, auth_token]):
    print("Error: Essential configuration missing. Ensure CVE List Name, Image, and Authorization Token are specified.")
    sys.exit(1)

# Set up authentication header
auth_header = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": f"Basic {auth_token}"
}

# use entity id for List creation
entity_id = get_entity_id(image_name_to_search, auth_header)
if not entity_id:
    exit("Entity ID could not be retrieved, exiting.")

api_url = "https://api.eu1.dome9.com/v2/GenericList"

# Read CVEs from Excel
current_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(current_dir, 'imagereport.xlsx')
df = pd.read_excel(file_path, sheet_name='CVE')

if 'name' in df.columns and 'Exclusion' in df.columns:
    df['Exclusion'] = df['Exclusion'].astype(str).str.upper()
    cve_list = df[df['Exclusion'] == 'X']['name'].dropna().unique().tolist()
else:
    exit("Missing required columns in Excel sheet.")

# Create chunks of CVEs
cve_entries = [
    {"value": f"{entity_id}#{'|'.join(chunk)}"}
    for chunk in chunk_cve_list(cve_list)
]

# Retrieve list to get the id (if it exists)
list_id = None
response = requests.get(api_url, headers=auth_header)
if response.ok:
    for item in response.json():
        if item['name'] == search_name:
            list_id = item['id']
            break
else:
    exit(f"Failed to retrieve lists: {response.status_code}")

# Create or update the list
# If list_id is None, it means we are creating a new list
# If list_id is not None, we are updating an existing list
payload = {
    "name": search_name,
    "items": cve_entries
}
if list_id:
    payload["id"] = list_id

# If the list exists, DELETE it before creating a new one
if list_id:
    delete_response = requests.delete(f"{api_url}/{list_id}", headers=auth_header)
    if not delete_response.ok:
        exit(f"Failed to delete list '{search_name}': {delete_response.status_code} - {delete_response.text}")

# Since we deleted the list if it existed, we no longer need to do an update (PUT),
# we always create a new list (POST)
create_response = requests.post(api_url, headers=auth_header, json=payload)
if create_response.ok:
    print(f"List '{search_name}' created successfully.")
else:
    print(f"Failed to create list '{search_name}': {create_response.status_code} - {create_response.text}")
    print(create_response.json())
