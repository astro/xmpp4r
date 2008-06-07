require 'dbus'
require 'xmpp4r'

Thread::abort_on_exception = true
Jabber::debug = true

class String
  def to_bytes
    scan(/./).collect { |c| c[0] }
  end
end

module Zeroconf
  SRV_TYPE = '_presence._tcp'

  class CannotConnect < StandardError
    def initialize(e)
      @e = e
    end
  end

  class Peer < Jabber::Connection
    attr_reader :name, :address, :presence_info

    def initialize(client, params)
      @lock = Mutex.new
      @lock.synchronize do
        @client = client
        @interface, @protocol, @name, @type, @domain, @host, @aprotocol, @address, @port, txt, flags = params
        @presence_info = {}
        txt.each do |s|
          str = s.collect { |c| c.chr }.to_s
          k, v = str.split('=', 2)
          @presence_info[k] = v
        end

        super(true)
        @features_timeout = 1
      end
    end

    def nick_name
      @presence_info["nick"]
    end

    def status
      @presence_info["status"]
    end
    
    def status_msg
      @presence_info["msg"]
    end
    
    def first_name
      @presence_info["1st"]
    end
    
    def last_name
      @presence_info["last"]
    end

    def send(stanza)
      @lock.synchronize do
        unless is_connected?
          connect(@address, @port || @presence_info["port.p2pj"].to_i)
          puts "connected to #{@address}"
          send_data generate_stream_start(@name, @client.name)
          puts "starting"
          #start
          puts "started"
        end

        super
      end
    end

    def receive(element)
      unless element.name == 'stream' and
          element.namespace == 'http://etherx.jabber.org/streams' and
          element.namespace('') == 'jabber:client'
        @client.receive(@address, element)
      else
        p element
      end
    end
  end

  class Server < Jabber::Stream
    def self.new_listener(client, port)
      Thread.new do
        server_socket = TCPServer.new(port)
        while client_socket = server_socket.accept
          begin
            new(client, client_socket)
          rescue
            p $!
          end
        end
      end.abort_on_exception = true
    end

    def initialize(client, socket)
      @client = client
      @first_stanza = false
      @peer_addr = socket.peeraddr[3]

      super(true)
      start(socket)
    end

    def receive(element)
      if @first_stanza
        @client.receive(@peer_addr, element)
      else
        if element.name == 'stream' and
            element.namespace == 'http://etherx.jabber.org/streams'
            element.namespace('') == 'jabber:client'
          send("<stream:stream " \
               "xmlns='jabber:client' " \
               "xmlns:stream='http://etherx.jabber.org/streams' " \
               "from='#{@client.name}' " \
               "to='#{element.attributes['from']}' " \
               "version='1.0'>")
          @first_stanza = true
        else
          raise element.to_s
        end
      end
    end
  end

  class Client < Jabber::Stream
    attr_reader :name, :my_presence_info

    def initialize(name, presence_info={}, port=5900)
      super(true)

      @name = name
      @port = port # TODO: randomize
      @my_presence_info = { 
        "txtvers"=>"1",
        "vc"=>"0",
        "port.p2pj"=>port.to_s,
      }
      presence_info.each { |k,v|
        @my_presence_info[k.to_s] = v
      }
      @peers = []
      @avahi_lock = Mutex.new
      Server.new_listener(self, port)
      publish
      #Thread.new {
        start_browser
      #}
    end

    def peers
      @peers.collect { |peer| peer.name }.uniq
    end

    def [](name)
      r = @avahi_lock.synchronize {
        @peers.select { |peer| name == peer.name }
      }
      if r.empty?
        start_browser
        r = @peers.select { |peer| name == peer.name }
      end
      r
    end

    def receive(addr, element)
      # TODO: Spoof protection
      super(element)
    end

    def send(stanza)
      peers = self[stanza.to]

      if peers.empty?
        raise "Peer #{stanza.to} not found"
      else
        stanza.from = @name
        peers.sort { |a,b|
          case [a.is_connected?, b.is_connected?]
          when true, false
            1
          when false, true
            -1
          else
            0
          end
        }.each { |peer|
          begin
            peer.send(stanza)
            return true
          rescue SystemCallError
            puts "CAUGHT #{$!.inspect}"
          end
        }
        # All tried, nothing worked
        raise "Cannot connect to #{stanza.to}"
      end
    end

    private

    def avahi_server
      DBus::SystemBus.instance.introspect("org.freedesktop.Avahi","/")["org.freedesktop.Avahi.Server"]
    end

    # Resolver side

    def start_browser
      items = []

      @avahi_lock.synchronize do
        DBus::SystemBus.instance.add_match(DBus::MatchRule.new) do |*m|
          puts "MATCH: #{m.inspect}"
        end


        browser_path = avahi_server.ServiceBrowserNew(-1, -1,
                                                      SRV_TYPE,
                                                      '',
                                                      0).first
        browser = DBus::SystemBus.instance.introspect("org.freedesktop.Avahi", browser_path)
        browser.default_iface = "org.freedesktop.Avahi.ServiceBrowser"
        puts "pre on_signal"
        browser.on_signal("ItemNew") do |*a|
          p a
        end
        puts "post on_signal"
=begin
        match('signal', "org.freedesktop.Avahi.ServiceBrowser", browser_path) do |msg|
          case msg.member
          when "ItemNew"
            items << msg.params
          else
            p msg
          end
        end
=end
      end

      items.each do |params|
        resolve_service(*params)
      end
    end

    def resolve_service(interface, protocol, name, type, domain, flags)
      @avahi_lock.synchronize {
        resolver_path = avahi_server.ServiceResolverNew(interface, protocol, name, type, domain, -1, 0).first

        match('signal', "org.freedesktop.Avahi.ServiceResolver", resolver_path) do |msg|
          case msg.member
          when "Found"
            peer = Peer.new(self, msg.params)
            @peers.delete_if { |apeer| peer.name == apeer.name and peer.address == apeer.address }
            p [peer.name, peer.address, peer.presence_info]
            @peers << peer
          else
            p msg
          end
        end
        resolver = DBus::SystemBus.instance.introspect("org.freedesktop.Avahi", resolver_path)["org.freedesktop.Avahi.ServiceResolver"]
        resolver.Free
      }
    end

    def match(type, interface, path, &block)
      mr = DBus::MatchRule.new
      mr.type = type
      mr.interface = interface
      mr.path = path
      DBus::SystemBus.instance.add_match(mr, &block)
    end

    # Publisher side

    public

    def publish
      @avahi_lock.synchronize {
        # TODO: utf-8?
        txt = @my_presence_info.collect { |k,v| k.to_bytes + [?=] + v.to_bytes}
        p txt

        if @entry_group
          @entry_group.UpdateServiceTxt(-1, -1, 0, @name, SRV_TYPE, '', txt)
        else
          entry_group_path = avahi_server.EntryGroupNew.first
          @entry_group = DBus::SystemBus.instance.introspect("org.freedesktop.Avahi", entry_group_path)["org.freedesktop.Avahi.EntryGroup"]
          @entry_group.AddService(-1, -1, 0, @name, SRV_TYPE, '', '', @port, txt)
          @entry_group.Commit
        end
      }
    end
  end
end


cl = Zeroconf::Client.new('broad@cast',
                          :nick=>'Broadcast',
                          '1st'=>'Broad',
                          :last=>'Cast',
                          :status=>'chat',
                          :msg=>'Broadcasting your messages...',
                          :jid=>'astro@spaceboyz.net')
whitelist = []
blacklist = []
cl.add_message_callback { |msg|
  if msg.type != :error and msg.body
    sender = nil
    cl[msg.from].each { |peer|
      sender = (peer.nick_name || "#{peer.first_name} #{peer.last_name}").to_s.strip
      sender = peer.name if sender.empty?
      break if sender
    }

    puts "*** Peers: #{cl.peers.inspect}"
    cl.peers.each { |name|
      next if name == cl.name # Me
      next if blacklist.include? name

      Thread.new {
        begin
          cl.send(Jabber::Message.new(name, "<#{sender}> #{msg.body}").set_type(msg.type))
          whitelist << name
        rescue
          p $!
          blacklist << name
          cl.my_presence_info['msg'] = "Reachable: #{whitelist.uniq.join', '} \nUnreachable: #{blacklist.uniq.join', '}"
          cl.publish
        end
      }
    }
  end
}

Thread.new {
begin
loop = DBus::Main.new
loop << DBus::SystemBus.instance
loop.run
rescue Errno::EAGAIN
  sleep 1
end
}
Thread.stop
