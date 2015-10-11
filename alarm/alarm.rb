require 'packetfu'
require 'optparse'

$incident_number = 0

Options = Struct.new(:logfile, :interface, :protocol)

class Parser
  def self.parse(options)

    args = Options.new()

    #defaults
    args.interface = 'eth0'
    args.protocol = 'tcp'

    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: alarm.rb [options]"

      opts.on("-r", "--logFilename=NAME", "Name of log file") do |r|
        args.logfile = r
      end

      opts.on("-i", "--interface=NAME", "Name of interface") do |i|
        args.interface = i
      end

      opts.on("-p", "--protocol=NAME", "Name of protocol") do |p|
        args.protocol = p
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

####################################################
# Analyze Live Stream of Network Packets Functions #
####################################################

# returns true if the packet is from a NULL scan
def is_null_scan?(packet)
  return packet.tcp_header.tcp_flags.to_i == 0
end

# returns true if the packet is from a FIN scan
def is_fin_scan?(packet)
  return packet.tcp_header.tcp_flags.to_i == 1
end

# returns true if the packet is from an Xmas scan
def is_xmas_scan?(packet)
  return packet.tcp_header.tcp_flags.to_i == 41
end

# returns true if the packet is from another Nmap scan
def is_nmap_scan?(packet)
  payload = packet.tcp_header.body
  return payload.downcase.include? "nmap"
end

#Nikto scan
def is_nikto_scan?
  return false
end

#Credit card leak
def is_credit_card_leak?
  #http://www.richardsramblings.com/regex/credit-card-numbers/
  return false
end

####################################
# Analyze Web Server Log Functions #
####################################

#TBD

def reportIncident(incident, source_ip, protocol, payload)
   $incident_number += 1
   puts "#{$incident_number}. ALERT: #{incident} is detected from #{source_ip} (#{protocol}) (#{payload})!"
end

if options.logfile
  #TBD
else
  cap = PacketFu::Capture.new(:iface => options.interface, :start => true, :promisc => true, :filter => options.protocol)
  cap.stream.each do |p|
    incident = "None"
    pkt = PacketFu::Packet.parse(p)

    if is_null_scan?(pkt)
      incident = "NULL Scan"
    elsif is_fin_scan?(pkt)
      incident = "FIN Scan"
    elsif is_xmas_scan?(pkt)
      incident = "Xmas Scan"
    end
    
    if incident != "None"
      reportIncident(incident, pkt.ip_saddr, options.protocol, pkt.tcp_header.body)
    end
  end
end

#stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
#stream.show_live()
