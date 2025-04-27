require_relative './libronsolve'
require 'httparty'

# Retrieve the file
PATH = get_url()
# PATH = "https://#{ HOST }:#{ PORT }/"
puts "Requesting #{ PATH }..."
out = ::HTTParty.get(PATH, verify: false)

if !out
  puts "Couldn't connect to #{ PATH }!"
  exit 1
end

if out.parsed_response =~ /(CTF{[^}]*})/
  check_flag(::Regexp.last_match(0), terminate: true)
else
  puts 'Did see anything flag-looking on the page!'
  exit 1
end
