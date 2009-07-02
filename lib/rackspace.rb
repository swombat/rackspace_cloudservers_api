#
# Copyright (c) 2007-2009 RightScale Inc
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
    class Interface

      def login
        authenticate
      end

      #--------------------------------
      # Images
      #--------------------------------

      # List images.
      def list_images(opts={})
        api_or_cache(:get, detailed_path("/images", opts), opts.merge(:incrementally => true))
      end

      # NOT TESTED
      def incrementally_list_images(offset=nil, limit=nil, opts={}, &block)
        incrementally_list_resources(:get, detailed_path("/images", opts), offset, limit, opts, &block)
      end

      # Get image data.
      def get_image(image_id, opts={})
        api(:get, "/images/#{image_id}", opts)
      end

      # NOT TESTED
      def create_image(server_id, name, opts={})
        body = { 'image' => { 'name' => name } }
        api(:post, "/servers/#{server_id}/actions/create_image",  opts.merge(:body => body.to_json))
      end

      #--------------------------------
      # Flavors
      #--------------------------------

      # List flavors.
      def list_flavors(opts={})
        api_or_cache(:get, detailed_path("/flavors", opts), opts.merge(:incrementally => true))
      end

      # NOT TESTED
      def incrementally_list_flavors(offset=nil, limit=nil, opts={}, &block)
        incrementally_list_resources(:get, detailed_path("/flavors", opts), offset, limit, opts, &block)
      end

      # Get flavor data.
      def get_flavor(flavor_id, opts={})
        api(:get, "/flavors/#{flavor_id}", opts)
      end

      #--------------------------------
      # Servers
      #--------------------------------

      # List servers.
      def list_servers(opts={})
        api_or_cache(:get, detailed_path("/servers", opts), opts.merge(:incrementally => true))
      end

      # NOT TESTED
      def incrementally_list_servers(offset=nil, limit=nil, opts={}, &block)
        incrementally_list_resources(:get, detailed_path("/servers", opts), offset, limit, opts, &block)
      end

      # Launch a new server.
      #  +Server_data+ is a hash of params params:
      #   Mandatory: :name, :image_id, :flavor_id
      #   Optional:  :password, :metadata, :files
      # TODO: A password setting does not seem to be working
      def create_server(server_data, opts={} )
        personality = server_data[:files].to_a.dup
        personality.map! { |file, contents| { 'path'=> file, 'contents' => Base64.encode64(contents).chomp } }
        body = {
          'server' => {
            'name'     => server_data[:name],
            'imageId'  => server_data[:image_id],
            'flavorId' => server_data[:flavor_id]
          }
        }
        body['server']['adminPass']   = server_data[:password] if     server_data[:password]
        body['server']['metadata']    = server_data[:metadata] unless server_data[:metadata].blank?
        body['server']['personality'] = personality            unless personality.blank?
        api(:post, "/servers", opts.merge(:body => body.to_json))
      end

      # Get a server data.
      def get_server(server_id, opts={})
        api(:get, "/servers/#{server_id}", opts)
      end

      # Change server name and/or password.
      # NOT TESTED
      def update_server(server_id, server_data, opts={})
        body = { 'server' => {} }
        body['server']['name']      = server_data[:name]     if server_data[:name]
        body['server']['adminPass'] = server_data[:password] if server_data[:password]
        api(:put, "/servers/#{server_id}", opts.merge(:body => body.to_json))
      end

      # NOT TESTED
      def reboot_server(server_id, type = :soft, opts={})
        body = { 'reboot' => { 'type' => type.to_s.upcase } }
        api(:post, "/servers/#{server_id}/actions/reboot", opts.merge(:body => body.to_json))
      end

      # NOT TESTED
      def rebuild_server(server_id, image_id, opts={})
        body = { 'rebuild' => { 'imageId' => image_id } }
        api(:post, "/servers/#{server_id}/actions/rebuild", opts.merge(:body => body.to_json))
      end

      # NOT TESTED
      def resize_server(server_id, flavor_id, opts={})
        body = { 'resize' => { 'flavorId' => flavor_id } }
        api(:post, "/servers/#{server_id}/actions/resize", opts.merge(:body => body.to_json))
      end

      # NOT TESTED
      def confirm_resized_server(server_id, opts={})
        api(:put, "/servers/#{server_id}/actions/resize", opts)
      end

      # NOT TESTED
      def revert_resized_server(server_id, opts={})
        api(:delete, "/servers/#{server_id}/actions/resize", opts)
      end

      # NOT TESTED
      def share_ip_address(server_id, shared_ip_group_id, address, opts={})
        body = { 
          'shareIp' => {
            'sharedIpGroupId' => shared_ip_group_id,
            'addr'            => address
          }
        }
        api(:post, "/servers/#{server_id}/actions/share_ip",  opts.merge(:body => body.to_json))
      end

      # NOT TESTED
      def unshare_ip_address(server_id, address, opts={})
        body = { 'unshareIp' => { 'addr' => address } }
        api(:post, "/servers/#{server_id}/actions/unshare_ip",  opts.merge(:body => body.to_json))
      end

      # Delete a server.
      # Returns +true+ on success.
      def delete_server(server_id, opts={})
        api(:delete, "/servers/#{server_id}", opts)
      end

      #--------------------------------
      # Backup Schedules
      #--------------------------------

      # NOT TESTED
      def get_backup_schedule(server_id, opts={})
        api(:get, "/servers/#{server_id}/backup_schedule", opts)
      end

      # NOT TESTED
      def update_backup_schedule(server_id, enabled, daily=nil, weekly=nil, opts={})
        body = { 'backupSchedule' => { 'enabled' => enabled.to_s } }
        body['backupSchedule']['daily']  = daily  unless daily.blank?
        body['backupSchedule']['weekly'] = weekly unless weekly.blank?
        api(:post, "/servers/#{server_id}/backup_schedule", opts.merge(:body => body.to_json))
      end

      # NOT TESTED
      def delete_backup_schedule(server_id, opts={})
        api(:delete, "/servers/#{server_id}/backup_schedule", opts)
      end

      #--------------------------------
      # Shared IP Groups
      #--------------------------------

      # NOT TESTED
      def list_shared_ip_groups(opts={})
        api_or_cache(:get, detailed_path("/shared_ip_groups", opts), opts.merge(:incrementally => true))
      end

      # NOT TESTED
      def incrementally_list_groups(offset=nil, limit=nil, opts={}, &block)
        incrementally_list_resources(:get, detailed_path("/groups", opts), offset, limit, opts, &block)
      end

      # NOT TESTED
      def create_shared_ip_groups(name, server_id=nil, opts={})
        body = { 'sharedIpGroup' => { 'name' => name } }
        body['sharedIpGroup']['server'] = server_id unless server_id.blank?
        api(:post, "/shared_ip_groups", opts.merge(:body => body.to_json))
      end

      # NOT TESTED
      def get_shared_ip_group(shared_ip_group_id, opts={})
        api(:get, "/shared_ip_groups/#{shared_ip_group_id}", opts)
      end

      # NOT TESTED
      def delete_shared_ip_group(shared_ip_group_id, opts={})
        api(:delete, "/shared_ip_groups/#{shared_ip_group_id}", opts)
      end

    end
  end
end