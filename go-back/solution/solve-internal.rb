require 'English'

CHOICES = ('a'..'z').to_a + ('A'..'Z').to_a + ['{', '}', '-']

str = ''
loop do
  puts str

  if str.end_with?('}')
    puts "XXX#{ str }XXX"
    exit 0
  end


  0x21.upto(0x7f) do |i|
    c = i.chr

    if c == "'"
      next
    end

    system("#{ ARGV[0] || './go-back' } '#{ str }#{ c }'")
    s = $CHILD_STATUS.exitstatus

    if(s == 1)
      str << (i + 1).chr
      break
    elsif(s == 255)
      str << (i - 1).chr
      break
    elsif(s == 0)
      check_flag(str, terminate: true)
    end
  end
end
