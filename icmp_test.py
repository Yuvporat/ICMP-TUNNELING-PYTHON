import requests
import json
url  = 'http://xn--9dbcb2e.com/'
response = requests.get(url=url)
if response.status_code == 200:
    # print('response.headers:',response.headers)
    response_headers_dict = dict(response.headers)

    # Serialize the dictionary to a JSON-formatted string
    json_headers = json.dumps(response_headers_dict, ensure_ascii=False)

    # Now, 'json_headers' contains the response headers in JSON format
    # print('json_headers:',json_headers)

    msg = '{}@#$%{}@#$%{}'.format(response.status_code,json_headers,response.text)
    # print(msg)
    with open('haruz.txt', "w", encoding="utf-8") as file:  # Specify UTF-8 encoding
        file.write(msg)




import json
with open('haruz.txt', 'r', encoding='utf-8') as file:
    # Read the content of the file into a string variable
    file_content = file.read()
data_split = file_content.split('@#$%')
status = int(data_split[0])
# Replace single quotes with double quotes to make it valid JSON

# Parse the JSON string into a dictionary
headers = json.loads(data_split[1])


content = data_split[2]
print(status,headers,content)
# response_headers_str = headers.replace("'", "\"")
# response_headers_dict = json.loads(response_headers_str)
# print('content:',content)
