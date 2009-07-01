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

      def list_images(opts={})
        api_or_cache(:get, detailed_path("/images", opts), opts)
      end

      def get_image(id, opts={})
        api(:get, "/images/#{id}", opts)
      end

      #--------------------------------
      # Flavors
      #--------------------------------

      def list_flavors(opts={})
        api_or_cache(:get, detailed_path("/flavors", opts), opts)
      end

      def get_flavor(id, opts={})
        api(:get, "/flavors/#{id}", opts)
      end

      #--------------------------------
      # Servers
      #--------------------------------

      def list_servers(opts={})
        api_or_cache(:get, detailed_path("/servers", opts), opts)
      end

      #--------------------------------
      # Shared IP Groups
      #--------------------------------

      def list_shared_ip_groups(opts={})
        api_or_cache(:get, detailed_path("/list_shared_ip_groupsss", opts), opts)
      end

    end
  end
end