require_relative 'libronsolve'

EXE = File.join(__dir__, '..', 'challenge', 'src', 'bug-me')
if `#{ EXE } \"#{ expected_flag() }\"` =~ /YAY/
  if `#{ EXE } \"cTF{hope-you-enjoyed-this-one}\"` =~ /YAY/
    raise 'Uh oh, a bad flag worked!'
  end

  puts 'Looks good!'
  exit(0)
end

raise "Uh oh, the correct flag didn't work!"
