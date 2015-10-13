# coding: utf-8
require 'packetfu'
require 'optparse'

$incident_number = 0

Options = Struct.new(:logfile, :interface)

class Parser
  def self.parse(options)

    args = Options.new()

    #defaults
    args.interface = 'eth0'

    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: alarm.rb [options]"

      opts.on("-r", "--logFilename=NAME", "Name of log file") do |r|
        args.logfile = r
      end

      opts.on("-i", "--interface=NAME", "Name of interface") do |i|
        args.interface = i
      end

      opts.on("-h", "--help", "Prints this help") do
        puts opts
        exit
      end
    end

    opt_parser.parse!(options)
    return args
  end
end

options = Parser.parse ARGV

####################################
# Analyze Web Server Log Functions #
####################################

# returns true if str_val contains the substring "nmap"
def contains_nmap?(str_val)
  return (str_val.downcase.include? "nmap" or
          str_val.downcase.include? "\6e\6d\61\70")
end

# returns true if str_val contains the substring "nikto"
def contains_nikto?(str_val)
  return (str_val.downcase.include? "nikto" or
          str_val.downcase.include? "\6e\69\6b\74\6f")
end

# returns true if str_val contains the substring "masscan"
def contains_masscan?(str_val)
  return (str_val.downcase.include? "masscan" or
          str_val.downcase.include? "\6d\61\73\73\63\61\6e")
end

# returns true if str_val contains the substring "shellshock-scan"
def contains_shellshock_scan?(str_val)
  return (str_val.downcase.include? "shellshock-scan" or
          str_val.downcase.include? "\73\68\65\6c\6c\73\68\6f\63\6b\2d\73\63\61\6e")
end

# returns true if str_val contains the substring "phpMyAdmin"
def contains_phpMyAdmin?(str_val)
  return (str_val.downcase.include? "phpmyadmin" or
          str_val.downcase.include? "\70\68\70\6d\79\61\64\6d\69\6e")
end

# returns true if str_val contains shellcode
def contains_shell_code?(str_val)
  shell_strings = ["/bin/bash", "rm -rf", "{ :; }", ".sh"]
  shell_strings.each do |ss|
    return true if str_val.include? ss
  end
  return false
end

def parseLogLine(logLine)
  protocol = "unknown"
  user_agent = ""
  
  ip_match = /^[[0-9].]+/.match(logLine)
  remaining_str = ip_match.post_match.strip
  source_ip_addr = ip_match.to_a[0]
  identity_match = /^(-|[\w.\s]+)/.match(remaining_str)
  remaining_str = identity_match.post_match.strip
  userid_match = /^(-|[\w.\s]+)/.match(remaining_str)
  remaining_str = userid_match.post_match.strip
  datetime_match = /^\[[^\[\]]+\]/.match(remaining_str)
  remaining_str = datetime_match.post_match.strip
  payload_match = /^"[^"]*"/.match(remaining_str)
  payload = payload_match.to_a[0]
  if not payload.empty? and not payload == "\"\""
    protocol_match = /\s[^\s"]+"$/.match(payload)
    protocol_match_arr = protocol_match.to_a
    if not protocol_match_arr[0].nil?
      protocol = protocol_match_arr[0].strip.chomp("\"")
    end
  end

  remaining_str = payload_match.post_match.strip
  status_code_match = /^\d{3}/.match(remaining_str)
  remaining_str = status_code_match.post_match.strip
  resp_byte_count_match = /^(-|[0-9]+)/.match(remaining_str)
  remaining_str = resp_byte_count_match.post_match.strip
  
  # Combined log format has two addtl pieces of information:
  #  1. referer and 2. user agent
  if not remaining_str.empty?
    referer_match = /^"[^"]+"/.match(remaining_str)
    remaining_str = referer_match.post_match.strip
    user_agent_match = /^"[^"]+"/.match(remaining_str)
    user_agent = user_agent_match.to_a[0]
    remaining_str = user_agent_match.post_match.strip
  end
  
  return source_ip_addr, payload, protocol, user_agent
  
end

####################################################
# Analyze Live Stream of Network Packets Functions #
####################################################

# returns true if the packet is from a NULL scan
def is_null_scan?(packet)
  return (packet.is_tcp? and (packet.tcp_header.tcp_flags.to_i == 0))
end

# returns true if the packet is from a FIN scan
def is_fin_scan?(packet)
  return (packet.is_tcp? and (packet.tcp_header.tcp_flags.to_i == 1))
end

# returns true if the packet is from an Xmas scan
def is_xmas_scan?(packet)
  return (packet.is_tcp? and (packet.tcp_header.tcp_flags.to_i == 41))
end

# returns true if the packet is from another Nmap scan
def is_nmap_scan?(packet)
  return (contains_nmap?(packet.tcp_header.body) or
          contains_nmap?(packet.payload))
end

# returns true if the packet is from a Nikto scan
def is_nikto_scan?(packet)
  return contains_nikto?(packet.payload)
end

# returns true if the packet contains a credit card leak
def is_credit_card_leak?(packet)
  check_str = packet.payload
  check_str.tr!('-', '')
  check_str.gsub!(/\s+/, '')

  cc_regex = "(?:" +
              "4[0-9]{12}(?:[0-9]{3})?"        +   # Visa
             "|5[1-5][0-9]{14}"                +   # MasterCard
             "|3[47][0-9]{13}"                 +   # American Express
             "|3(?:0[0-5]|[68][0-9])[0-9]{11}" +   # Diners Club
             "|6(?:011|5[0-9]{2})[0-9]{12}"    +   # Discover
             "|(?:2131|1800|35\d{3})\d{11}"    +   # JCB
             ")"

  cc_match = /#{cc_regex}/.match(check_str)
  return (not cc_match.to_a[0].nil?)
end 

def reportIncident(incident, source_ip, protocol, payload)
   $incident_number += 1
   puts "#{$incident_number}. ALERT: #{incident} is detected from #{source_ip} (#{protocol}) (#{payload})!"
end

##############
# BEGIN MAIN #
##############

if options.logfile
  File.readlines(options.logfile).each do |line|
    source_ip_addr, payload, protocol, user_agent = parseLogLine(line)
    incident = "None"

    if contains_phpMyAdmin?(payload)
      incident = "Something involving phpMyAdmin"
    elsif not user_agent.empty?
      if contains_nmap?(user_agent)
        incident = "Nmap Scan"
      elsif contains_nikto?(user_agent)
        incident="Nikto Scan"
      elsif contains_masscan?(user_agent)
        incident="Masscan"
      elsif contains_shellshock_scan?(user_agent)
        incident="Shellshock Vulnerability Scan"
      elsif contains_shell_code?(user_agent)
        incident="Somthing involving shellcode"
      end
    end

    if incident != "None"
      reportIncident(incident, source_ip_addr, protocol, payload)
    end
    
  end
  
else #live capture
  cap = PacketFu::Capture.new(:iface => options.interface, :start => true, :promisc => true)
  cap.stream.each do |p|
    incident = "None"
    pkt = PacketFu::Packet.parse(p)

    if is_nikto_scan?(pkt)
      incident = "Nikto Scan"
    elsif is_null_scan?(pkt)
      incident = "NULL Scan"
    elsif is_fin_scan?(pkt)
      incident = "FIN Scan"
    elsif is_xmas_scan?(pkt)
      incident = "Xmas Scan"
    elsif is_nmap_scan?(pkt)
      incident = "Nmap Scan"
    elsif is_credit_card_leak?(pkt)
      incident = "Credit Card Leak"
    end
    
    if incident != "None"
      reportIncident(incident, pkt.ip_saddr, pkt.proto.last, pkt.payload)
    end
    
  end
end
