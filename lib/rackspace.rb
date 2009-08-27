#
# Copyright (c) 2009 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#
module Rightscale
  module Rackspace

    # TODO: KD: Enable this feature when Packspace get rid of the caching issue
    PAGINATION_ENABLED = false

    # == Rightscale::Rackspace::Interface 
    #
    # === Examples:
    #
    #  # Create a handle
    #  rackspace = Rightscale::Rackspace::Interface::new('uw1...cct', '99b0...047d', :verbose_errors => true )
    #
    #  # list images and flavors
    #  rackspace.list_images(:detaile => true)
    #  rackspace.list_flavors(:detaile => true)
    #
    #  # launch a new server
    #  image_id = 8
    #  flavor_id = 4
    #  new_server = rackspace.create_server('my-awesome-server', image_id, flavor_id,
    #                                       :metadata => {
    #                                         'metakey1' => 'metavalue1',
    #                                         'metakey2' => 'metavalue2',
    #                                         'metakey3' => 'metavalue3' },
    #                                       :personalities => {
    #                                         '/home/file1.txt' => 'ohoho!',
    #                                         '/home/file2.txt' => 'ahaha!',
    #                                         '/home/file3.rb' => 'puts "Olalah!"'}
    #
    #  puts "New server password is: #{new_server['server']['adminPass']}"
    #
    #  # change the server password
    #  rackspace.update_server(new_server['server']['id'], 'my_new_password')
    #
    #  # "upgrade" the server
    #  new_flavor_id = 6
    #  rackspace.resize_server(new_server['server']['id'], new_flavor_id)
    #  rackspace.confirm_resized_server(new_server['server']['id'])
    #
    #  # make an image from the server
    #  new_image = rackspace.create_image(new_server['server']['id'], 'my-awesome-image-0001')
    #
    #  # make a hard reboot (power off)
    #  rackspace.reboot_server(new_server['server']['id'], :hard)
    #
    #  # delete the server
    #  rackspace.delete_server(new_server['server']['id'])
    #
    # === RightRackspace gem caching usage (only list_xxx calls). This caching does not hit if any additional URL variables are set through :vars hash.
    #
    #  # Create a handle
    #  rackspace = Rightscale::Rackspace::Interface::new('uw1...cct', '99b0...047d', :caching => true)
    #
    #  # make a call. this fills the internal cache with the response and
    #  # a current timestamp
    #  old_list = rackspace.list_servers(:detail => true)
    #
    #  # sleep a bit
    #  sleep 5
    #
    #  # make another call
    #  begin
    #    new_list = rackspace.list_servers(:detail => true)
    #  rescue Rightscale::Rackspace::NoChange
    #    puts e.message #=> "Cached: '/servers/detail' has not changed since Thu, 09 Jul 2009 10:53:35 GMT."
    #    # extract the list of servers from internal cache
    #    new_list = rackspace.cache['/servers/detail'][:data]
    #    # the lists must be equal
    #    puts old_list == new_list
    #  end
    #
    #  # non detailed list of servers
    #  rackspace.list_servers
    #  begin
    #    flavors = rackspace.list_servers
    #  rescue Rightscale::Rackspace::NoChange
    #    flavors = rackspace.cache['/servers'][:data]
    #  ens
    #
    #  # this does not hit internal cache doe to the :vars.
    #  new_list = rackspace.list_servers(:detail => true, :vars => {'format' => 'json'})
    #
    # === Rackspace service caching usage:
    #
    #  # Create a handle
    #  rackspace = Rightscale::Rackspace::Interface::new('uw1...cct', '99b0...047d')
    #
    #  # 'if-modified-since' HTTP request header usage:
    #  last_request_time = Time.now - 3600
    #  begin
    #   rackspace.list_servers(:detail => true, :headers => { 'if-modified-since' => last_request_time })
    #  rescue Rightscale::Rackspace::NoChange => e
    #    # e.message can return one of the messages below:
    #    # - "Cached: '/servers/detail' has not changed since Thu, 09 Jul 2009 10:55:41 GMT."
    #    # - "NotModified: '/servers/detail' has not changed since Thu, 09 Jul 2009 10:55:41 GMT."
    #    # The first comes when we have cached response from Rackspace and it can be retreived as
    #    # rackspace.cache['/servers/detail'][:data]. The second one appears when the local
    #    # cache has no stored records for the request.
    #    puts e.message
    #  end
    #
    #  # 'changes-since' URL variable usage:
    #  begin
    #    new_servers = rackspace.list_servers(:detail => true, :vars => { 'changes-since' => last_request_time })
    #    # show the changes at servers since last_request_time
    #    puts new_servers.inspect
    #  rescue Rightscale::Rackspace::NoChange => e
    #    puts e.message #=>
    #      "NotModified: '/flavors?changes-since=1247137435&limit=1000&offset=0' has not changed since the requested time."
    #  end
    #
    # === Callbacks:
    #
    #  # On response calback
    #  on_response = Proc.new do |handle|
    #    puts ">> response headers: #{handle.last_response.to_hash.inspect}"
    #  end
    #
    #  # On error calback
    #  on_error = Proc.new do |handle, error_message|
    #    puts ">> Error: #{error_message}"
    #  end
    #
    #  # Create a handle
    #  rackspace = Rightscale::Rackspace::Interface::new('uw1...cct', '99b0...047d',
    #    :on_response => on_response,
    #    :on_error    => on_error)
    #
    class Interface

      # The login is executed automatically when one calls any othe API call.
      # The only use case  for this method is when one need to pass any custom
      # headers or URL vars during a login process.
      #
      #  rackspace.login #=> true
      #
      def login(opts={})
        authenticate(opts)
      end

      # List all API versions supported by a Service Endpoint.
      #
      #  rackspace.list_api_versions #=> {"versions"=>[{"id"=>"v1.0", "status"=>"BETA"}]}
      #
      #  RightRackspace caching: yes, key: '/'
      #
      def list_api_versions(opts={})
        api_or_cache(:get, "/",  opts.merge(:no_service_path => true))
      end

      # Determine rate limits.
      # 
      #  rackspace.list_limits #=> 
      #    {"limits"=>
      #      {"absolute"=>
      #        {"maxNumServers"=>25, "maxIPGroups"=>50, "maxIPGroupMembers"=>25},
      #       "rate"=>
      #        [{"regex"=>".*",
      #          "verb"=>"PUT",
      #          "URI"=>"*",
      #          "remaining"=>10,
      #          "unit"=>"MINUTE",
      #          "value"=>10,
      #          "resetTime"=>1246604596},
      #         {"regex"=>"^/servers",
      #          "verb"=>"POST",
      #          "URI"=>"/servers*",
      #          "remaining"=>1000,
      #          "unit"=>"DAY",
      #          "value"=>1000,
      #          "resetTime"=>1246604596}, ...]}}
      #
      #
      def list_limits(opts={})
#     # RightRackspace caching: yes, key: '/limits'
#        api_or_cache(:get, "/limits",  opts)
        api(:get, "/limits",  opts)
      end

      #--------------------------------
      # Images
      #--------------------------------

      # List images. Options: :detail => false|true.
      #
      #  # Get images list.
      #  rackspace.list_images #=>
      #    {"images"=>
      #      [{"name"=>"CentOS 5.2", "id"=>2},
      #       {"name"=>"Gentoo 2008.0", "id"=>3},
      #       {"name"=>"Debian 5.0 (lenny)", "id"=>4},
      #        ...}]}
      #
      #  # Get the detailed images description.
      #  rackspace.list_images(:detail => true) #=>
      #    {"images"=>
      #      [{"name"=>"CentOS 5.2", "id"=>2, "status"=>"ACTIVE"},
      #       {"name"=>"Gentoo 2008.0",
      #        "id"=>3,
      #        "updated"=>"2007-10-24T12:52:03-05:00",
      #        "status"=>"ACTIVE"},
      #       {"name"=>"Debian 5.0 (lenny)", "id"=>4, "status"=>"ACTIVE"},
      #       {"name"=>"Fedora 10 (Cambridge)", "id"=>5, "status"=>"ACTIVE"},
      #       {"name"=>"CentOS 5.3", "id"=>7, "status"=>"ACTIVE"},
      #       {"name"=>"Ubuntu 9.04 (jaunty)", "id"=>8, "status"=>"ACTIVE"},
      #       {"name"=>"Arch 2009.02", "id"=>9, "status"=>"ACTIVE"},
      #       {"name"=>"Ubuntu 8.04.2 LTS (hardy)", "id"=>10, "status"=>"ACTIVE"},
      #       {"name"=>"Ubuntu 8.10 (intrepid)", "id"=>11, "status"=>"ACTIVE"},
      #       {"name"=>"Red Hat EL 5.3", "id"=>12, "status"=>"ACTIVE"},
      #       {"name"=>"Fedora 11 (Leonidas)", "id"=>13, "status"=>"ACTIVE"},
      #       {"name"=>"my-awesome-image-0001",
      #        "serverId"=>62844,
      #        "progress"=>100,
      #        "id"=>3226,
      #        "updated"=>"2009-07-07T01:20:48-05:00",
      #        "status"=>"ACTIVE",
      #        "created"=>"2009-07-07T01:17:16-05:00"}]}
      #
      # RightRackspace caching: yes, keys: '/images', '/images/detail'
      #
      def list_images(opts={})
        api_or_cache(:get, detailed_path("/images", opts), opts.merge(:incrementally => PAGINATION_ENABLED))
      end

      # Incrementally list images.
      #
      #  # list images by 3
      #  rackspace.incrementally_list_images(0, 3, :detail=>true) do |response|
      #    puts response.inspect
      #    true
      #  end
      #
      def incrementally_list_images(offset=nil, limit=nil, opts={}, &block)
        incrementally_list_resources(:get, detailed_path("/images", opts), offset, limit, opts, &block)
      end

      # Get image data.
      #
      #  rackspace.get_image(5) #=>
      #    {"image"=>{"name"=>"Fedora 10 (Cambridge)", "id"=>5, "status"=>"ACTIVE"}}
      #
      def get_image(image_id, opts={})
        api(:get, "/images/#{image_id}", opts)
      end

      # Create a new image for the given server ID. Once complete, a new image will be
      # available that can be used to rebuild or create servers. Specifying the same image name as an
      # existing custom image replaces the image
      #
      #  # create an image
      #  new_image = rackspace.create_image(62844, 'my-awesome-image-0001') #=>
      #    {"image"=>{"name"=>"my-awesome-image-0001", "serverId"=>62844, "id"=>3226}}
      #
      #  # sleep a bit
      #  sleep 10
      #
      #  # get the new image status
      #  rackspace.get_image(new_image['image']['id']) #=>
      #    {"image"=>
      #      {"name"=>"my-awesome-image-0001",
      #       "progress"=>78,
      #       "id"=>3226,
      #       "updated"=>"2009-07-07T01:20:16-05:00",
      #       "status"=>"SAVING",
      #       "created"=>"2009-07-07T01:16:51-05:00"}}
      #
      #  # sleep more to make the new image active
      #  sleep 60
      #
      #  # list all the images
      #  rackspace.list_images(:detail => true) #=>
      #    {"images"=>
      #      [{"name"=>"CentOS 5.2", "id"=>2, "status"=>"ACTIVE"},
      #       {"name"=>"Gentoo 2008.0",
      #        "id"=>3,
      #        "updated"=>"2007-10-24T12:52:03-05:00",
      #        "status"=>"ACTIVE"},
      #       {"name"=>"Debian 5.0 (lenny)", "id"=>4, "status"=>"ACTIVE"},
      #       {"name"=>"Fedora 10 (Cambridge)", "id"=>5, "status"=>"ACTIVE"},
      #       {"name"=>"CentOS 5.3", "id"=>7, "status"=>"ACTIVE"},
      #       {"name"=>"Ubuntu 9.04 (jaunty)", "id"=>8, "status"=>"ACTIVE"},
      #       {"name"=>"Arch 2009.02", "id"=>9, "status"=>"ACTIVE"},
      #       {"name"=>"Ubuntu 8.04.2 LTS (hardy)", "id"=>10, "status"=>"ACTIVE"},
      #       {"name"=>"Ubuntu 8.10 (intrepid)", "id"=>11, "status"=>"ACTIVE"},
      #       {"name"=>"Red Hat EL 5.3", "id"=>12, "status"=>"ACTIVE"},
      #       {"name"=>"Fedora 11 (Leonidas)", "id"=>13, "status"=>"ACTIVE"},
      #       {"name"=>"my-awesome-image-0001",
      #        "serverId"=>62844,
      #        "progress"=>100,
      #        "id"=>3226,
      #        "updated"=>"2009-07-07T01:20:48-05:00",
      #        "status"=>"ACTIVE",
      #        "created"=>"2009-07-07T01:17:16-05:00"}]}
      #
      #
      def create_image(server_id, name, opts={})
        body = { 'image' => { 'name'     => name,
                              'serverId' => server_id } }
        api(:post, "/images",  opts.merge(:body => body.to_json))
      end

      #--------------------------------
      # Flavors
      #--------------------------------

      # List flavors. Options: :detail => false|true.
      #
      #  # Get list of flavors.
      #  rackspace.list_flavors #=>
      #    {"flavors"=>
      #      [{"name"=>"256 slice", "id"=>1},
      #       {"name"=>"512 slice", "id"=>2},
      #       {"name"=>"1GB slice", "id"=>3},
      #       ...}]}
      #
      #  # Get the detailed flavors description.
      #  rackspace.list_flavors(:detail => true) #=>
      #    {"flavors"=>
      #      [{"name"=>"256 slice", "id"=>1, "ram"=>256, "disk"=>10},
      #       {"name"=>"512 slice", "id"=>2, "ram"=>512, "disk"=>20},
      #       {"name"=>"1GB slice", "id"=>3, "ram"=>1024, "disk"=>40},
      #       ...}]}
      #
      #  # Get the most recent changes or Rightscale::Rackspace::NoChange.
      #  # (no RightRackspace gem caching)
      #  rackspace.list_flavors(:detail => true, :vars => {'changes-since'=>Time.now-3600}) #=>
      #
      # RightRackspace caching: yes, keys: '/flavors', '/flavors/detail'
      #
      def list_flavors(opts={})
        api_or_cache(:get, detailed_path("/flavors", opts), opts.merge(:incrementally => PAGINATION_ENABLED))
      end

      # Incrementally list flavors.
      #
      #  rackspace.incrementally_list_flavors(0,3) do |response|
      #    puts response.inspect
      #    true
      #  end
      #
      def incrementally_list_flavors(offset=nil, limit=nil, opts={}, &block)
        incrementally_list_resources(:get, detailed_path("/flavors", opts), offset, limit, opts, &block)
      end

      # Get flavor data.
      #
      #  rackspace.get_flavor(5) #=>
      #    {"flavor"=>{"name"=>"4GB slice", "id"=>5, "ram"=>4096, "disk"=>160}}
      #
      def get_flavor(flavor_id, opts={})
        api(:get, "/flavors/#{flavor_id}", opts)
      end

      #--------------------------------
      # Servers
      #--------------------------------

      # List servers. Options: :detail => false|true.
      #
      #  rackspace.list_servers #=>
      #    {"servers"=>[{"name"=>"my-super-awesome-server-", "id"=>62844}]}
      #
      #  rackspace.list_servers(:detail => true) #=>
      #    {"servers"=>
      #      [{"name"=>"my-super-awesome-server-",
      #        "addresses"=>
      #         {"public"=>["174.143.246.228"], "private"=>["10.176.134.157"]},
      #        "progress"=>100,
      #        "imageId"=>8,
      #        "metadata"=>{"data1"=>"Ohoho!", "data2"=>"Ehehe!"},
      #        "id"=>62844,
      #        "flavorId"=>3,
      #        "hostId"=>"fabfc1cebef6f1d7e4b075138dbd6b46",
      #        "status"=>"ACTIVE"}]
      #
      def list_servers(opts={})
        api_or_cache(:get, detailed_path("/servers", opts), opts.merge(:incrementally => PAGINATION_ENABLED))
      end

      # Incrementally list servers.
      #
      #  # list servers by 3
      #  rackspace.incrementally_list_servers(0, 3) do |response|
      #    puts response.inspect
      #    true
      #  end
      #
      def incrementally_list_servers(offset=nil, limit=nil, opts={}, &block)
        incrementally_list_resources(:get, detailed_path("/servers", opts), offset, limit, opts, &block)
      end

      # Launch a new server.
      #  +Server_data+ is a hash of params params:
      #   Mandatory: :name, :image_id, :flavor_id
      #   Optional:  :metadata, :personalities
      #
      #  rackspace.create_server(
      #    :name      => 'my-awesome-server',
      #    :image_id  => 8,
      #    :flavor_id => 4,
      #    :metadata  => { 'KD1' => 'XXXX1', 'KD2' => 'XXXX2'},
      #    :personalities => { '/home/1.txt' => 'woo-hoo',
      #                        '/home/2.rb'  => 'puts"Olalah!' }) #=>
      #    {"server"=>
      #      {"name"=>"my-awesome-server",
      #       "addresses"=>{"public"=>["174.143.56.6"], "private"=>["10.176.1.235"]},
      #       "progress"=>0,
      #       "imageId"=>8,
      #       "metadata"=>{"KD1"=>"XXXX1", "KD2"=>"XXXX2"},
      #       "adminPass"=>"my-awesome-server85lzHZ",
      #       "id"=>2290,
      #       "flavorId"=>4,
      #       "hostId"=>"19956ee1c79a57e481b652ddf818a569",
      #       "status"=>"BUILD"}}
      #
      def create_server(server_data, opts={} )
        personality = server_data[:personalities].to_a.dup
        personality.map! { |file, contents| { 'path'=> file, 'contents' => Base64.encode64(contents).chomp } }
        body = {
          'server' => {
            'name'     => server_data[:name],
            'imageId'  => server_data[:image_id],
            'flavorId' => server_data[:flavor_id],
          }
        }
        #body['server']['adminPass']   = server_data[:password] if     server_data[:password]
        body['server']['sharedIpGroupId']   = server_data[:shared_ip_group_id] if server_data[:shared_ip_group_id]
        body['server']['metadata']    = server_data[:metadata] unless server_data[:metadata].blank?
        body['server']['personality'] = personality            unless personality.blank?
        api(:post, "/servers", opts.merge(:body => body.to_json))
      end

      # Get a server data.
      #  rackspace.get_server(2290)
      #    {"server"=>
      #      {"name"=>"my-awesome-server",
      #       "addresses"=>{"public"=>["174.143.56.6"], "private"=>["10.176.1.235"]},
      #       "progress"=>100,
      #       "imageId"=>8,
      #       "metadata"=>{"KD1"=>"XXXX1", "KD2"=>"XXXX2"},
      #       "id"=>2290,
      #       "flavorId"=>4,
      #       "hostId"=>"19956ee1c79a57e481b652ddf818a569",
      #       "status"=>"ACTIVE"}}
      #
      def get_server(server_id, opts={})
        api(:get, "/servers/#{server_id}", opts)
      end

      # Change server name and/or password.
      # +Server_data+: :name, :password
      #
      #  rackspace.update_server(2290, :password => '12345' ) #=> true
      #  rackspace.update_server(2290, :name => 'my-super-awesome-server', :password => '67890' ) #=> true
      #
      # P.S. the changes will appers in some seconds.
      # 
      # P.P.S. changes server status: 'ACTIVE' -> 'PASSWORD'.
      #
      def update_server(server_id, server_data, opts={})
        body = { 'server' => {} }
        body['server']['name']      = server_data[:name]     if server_data[:name]
        body['server']['adminPass'] = server_data[:password] if server_data[:password]
        api(:put, "/servers/#{server_id}", opts.merge(:body => body.to_json))
      end

      # Reboot a server.
      #
      #  # Soft reboot
      #  rackspace.reboot_server(2290) #=> true
      #
      #  # Hard reboot (power off)
      #  rackspace.reboot_server(2290, :hard) #=> true
      #
      def reboot_server(server_id, type = :soft, opts={})
        body = { 'reboot' => { 'type' => type.to_s.upcase } }
        api(:post, "/servers/#{server_id}/action", opts.merge(:body => body.to_json))
      end

      # The rebuild function removes all data on the server and replaces it with the specified image. 
      # Server id and IP addresses will remain the same.
      #
      #  # rebuild a server
      #  rackspace.rebuild_server(62844, 3226) #=> true
      #
      #  # watch for the progress
      #  rackspace.get_server(62844) #=>
      #    {"server"=>
      #      {"name"=>"my-super-awesome-server-",
      #       "addresses"=>{"public"=>["174.143.246.228"], "private"=>["10.176.134.157"]},
      #       "progress"=>65,
      #       "imageId"=>3226,
      #       "metadata"=>{"data1"=>"Ohoho!", "data2"=>"Ehehe!"},
      #       "id"=>62844,
      #       "flavorId"=>3,
      #       "hostId"=>"fabfc1cebef6f1d7e4b075138dbd6b46",
      #       "status"=>"REBUILD"}}
      #
      def rebuild_server(server_id, image_id, opts={})
        body = { 'rebuild' => { 'imageId' => image_id } }
        api(:post, "/servers/#{server_id}/action", opts.merge(:body => body.to_json))
      end

      # The resize function converts an existing server to a different flavor, in essence, scaling the server up
      # or down. The original server is saved for a period of time to allow rollback if there is a problem. All
      # resizes should be tested and explicitly confirmed, at which time the original server is removed. All
      # resizes are automatically confirmed after 24 hours if they are not explicitly confirmed or reverted.
      #
      #  rackspace.resize_server(2290, 3) #=> true
      #  rackspace.get_server(2290) #=>
      #    {"server"=>
      #      {"name"=>"my-awesome-server",
      #       "addresses"=>{"public"=>["174.143.56.6"], "private"=>["10.176.1.235"]},
      #       "progress"=>0,
      #       "imageId"=>8,
      #       "metadata"=>{"KD1"=>"XXXX1", "KD2"=>"XXXX2"},
      #       "id"=>2290,
      #       "flavorId"=>4,
      #       "hostId"=>"19956ee1c79a57e481b652ddf818a569",
      #       "status"=>"QUEUE_RESIZE"}}
      #
      def resize_server(server_id, flavor_id, opts={})
        body = { 'resize' => { 'flavorId' => flavor_id } }
        api(:post, "/servers/#{server_id}/action", opts.merge(:body => body.to_json))
      end

      # Confirm a server resize action.
      #
      #  rackspace.confirm_resized_server(2290) #=> true
      #
      def confirm_resized_server(server_id, opts={})
        body = { 'confirmResize' => nil }
        api(:post, "/servers/#{server_id}/action", opts.merge(:body => body.to_json))
      end

      # Revert a server resize action.
      #
      #  rackspace.revert_resized_server(2290) #=> true
      #
      def revert_resized_server(server_id, opts={})
        body = { 'revertResize' => nil }
        api(:post, "/servers/#{server_id}/action", opts.merge(:body => body.to_json))
      end

      #--------------------------------
      # Server addresses
      #--------------------------------

      # Get server addresses.
      # 
      #  # get all addresses
      #  rackspace.list_addresses(62844) #=>
      #    {"addresses"=>{"public"=>["174.143.246.228"], "private"=>["10.176.134.157"]}}
      #
      #  # get public addresses
      #  rackspace.list_addresses(62844, :public) #=>
      #    {"public"=>["174.143.246.228"]}
      #
      #  # get private addresses
      #  rackspace.list_addresses(62844, :private) #=>
      #    {"private"=>["10.176.134.157"]}
      #
      # RightRackspace caching: no
      def list_addresses(server_id, address_type=:all, opts={})
        path = "/servers/#{server_id}/ips"
        case address_type.to_s
        when 'public'  then path += "/public"
        when 'private' then path += "/private"
        end
        api(:get, path, opts.merge(:incrementally => PAGINATION_ENABLED))
      end

      # Share an IP from an existing server in the specified shared IP group to another
      # specified server in the same group.
      #
      #  rackspace.share_ip_address(2296, 42, "174.143.56.6") #=> true
      #  
      #  rackspace.get_server(2290) #=>
      #    {"server"=>
      #      {"name"=>"my-awesome-server",
      #       "addresses"=>
      #        {"public"=>["174.143.56.6", "174.143.56.13"], "private"=>["10.176.1.235"]},
      #       "progress"=>100,
      #       "imageId"=>8,
      #       "metadata"=>{"KD1"=>"XXXX1", "KD2"=>"XXXX2"},
      #       "id"=>2290,
      #       "flavorId"=>3,
      #       "hostId"=>"1d5fa1271f57354d9e2861e848568eb3",
      #       "status"=>"SHARE_IP_NO_CONFIG"}}
      #
      def share_ip_address(server_id, shared_ip_group_id, address, configure_server=true, opts={})
        body = { 
          'shareIp' => {
            'sharedIpGroupId' => shared_ip_group_id,
            'configureServer' => configure_server
          }
        }
        api(:put, "/servers/#{server_id}/ips/public/#{address}",  opts.merge(:body => body.to_json))
      end

      # Remove a shared IP address from the specified server
      #
      #  rackspace.unshare_ip_address(2296, "174.143.56.6") #=> true
      #
      def unshare_ip_address(server_id, address, opts={})
        body = { 'unshareIp' => { 'addr' => address } }
        api(:delete, "/servers/#{server_id}/ips/public/#{address}",  opts.merge(:body => body.to_json))
      end

      # Delete a server.
      # Returns +true+ on success.
      #
      #  rackspace.delete_server(2284) #=> true
      #
      def delete_server(server_id, opts={})
        api(:delete, "/servers/#{server_id}", opts)
      end

      #--------------------------------
      # Backup Schedules
      #--------------------------------

      # Get the backup schedule for the specified server.
      # 
      #  rackspace.get_backup_schedule(62844) #=>
      #    {"backupSchedule"=>{"weekly"=>"DISABLED", "enabled"=>false, "daily"=>"DISABLED"}}
      #
      def get_backup_schedule(server_id, opts={})
        api(:get, "/servers/#{server_id}/backup_schedule", opts)
      end

      # Create a new backup schedule or updates an existing backup schedule for the specified server.
      # +Schedule_data+ is a hash:  :enabled, :daily, :weekly
      #
      #  # set just a daily backup
      #  rackspace.update_backup_schedule(62844, {:enabled => true, :daily => "H_0400_0600"}) #=> true
      #
      #  # set both the weekly and the daily schedules
      #  h.update_backup_schedule(62844, {:enabled => true, :daily => "H_0400_0600", :weekly => 'MONDAY'}) #=> true
      #
      #  # disable (delete) the schedule
      #  h.update_backup_schedule(62844, {:enabled => false}) #=> true
      #
      # P.S. the changes may appear in some seconds
      #
      def update_backup_schedule(server_id, schedule_data={}, opts={})
        body = { 'backupSchedule' => { 'enabled' => schedule_data[:enabled] ? true : false } }
        daily  = schedule_data[:daily].blank?  ? 'DISABLED' : schedule_data[:daily].to_s.upcase
        weekly = schedule_data[:weekly].blank? ? 'DISABLED' : schedule_data[:weekly].to_s.upcase
        body['backupSchedule']['daily']  = daily
        body['backupSchedule']['weekly'] = weekly
        api(:post, "/servers/#{server_id}/backup_schedule", opts.merge(:body => body.to_json))
      end

      # Deletes the backup schedule for the specified server.
      #
      #  h.delete_backup_schedule(62844) #=> true
      #
      # P.S. the changes may appear in some seconds
      #
      def delete_backup_schedule(server_id, opts={})
        api(:delete, "/servers/#{server_id}/backup_schedule", opts)
      end

      #--------------------------------
      # Shared IP Groups
      #--------------------------------

      # List shared IP groups. Options: :detail => false|true.
      #
      # RightRackspace caching: yes, keys: '/shared_ip_groups', '/shared_ip_groups/detail'
      #
      def list_shared_ip_groups(opts={})
        api_or_cache(:get, detailed_path("/shared_ip_groups", opts), opts.merge(:incrementally => PAGINATION_ENABLED))
      end

      # Incrementally list IP groups.
      #
      #  # list groups by 5
      #  rackspace.incrementally_list_shared_ip_groups(0, 5) do |x|
      #    puts x.inspect
      #    true
      #  end
      #
      def incrementally_list_shared_ip_groups(offset=nil, limit=nil, opts={}, &block)
        incrementally_list_resources(:get, detailed_path("/shared_ip_groups", opts), offset, limit, opts, &block)
      end

      # Create a new shared IP group.
      #
      #  rackspace.create_shared_ip_group('my_awesome_group', 2290) #=>
      #   {"sharedIpGroup"=>{"name"=>"my_awesome_group", "id"=>42}}
      #
      def create_shared_ip_group(name, server_id=nil, opts={})
        body = { 'sharedIpGroup' => { 'name' => name } }
        body['sharedIpGroup']['server'] = server_id unless server_id.blank?
        api(:post, "/shared_ip_groups", opts.merge(:body => body.to_json))
      end

      # Get shared IP group data.
      # 
      #   rackspace.list_shared_ip_groups #=>
      #    {"sharedIpGroups"=>[{"name"=>"my_awesome_group", "id"=>42, "servers"=>[2290]}]}
      #
      def get_shared_ip_group(shared_ip_group_id, opts={})
        api(:get, "/shared_ip_groups/#{shared_ip_group_id}", opts)
      end

      # Delete an IP group.
      #
      #   rackspace.delete_shared_ip_group(42) #=> true
      #
      def delete_shared_ip_group(shared_ip_group_id, opts={})
        api(:delete, "/shared_ip_groups/#{shared_ip_group_id}", opts)
      end

    end
  end
end