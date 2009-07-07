class TestCredentials

  @@username = nil
  @@auth_key = nil

  def self.username
    @@username
  end
  def self.username=(newval)
    @@username = newval
  end
  def self.auth_key
    @@auth_key
  end
  def self.auth_key=(newval)
    @@auth_key = newval
  end

# Make sure you have environment vars set:
#
# export RACKSPACE_USERNAME ='your_rackspace_username'
# export RACKSPACE_AUTH_KEY ='your_rackspace_auth_key'
#
# or you have a file: ~/.rightscale/test_rackspace_credentials.rb with text:
#
#  TestCredentials.key = 'your_rackspace_username'
#  TestCredentials.secret = 'your_rackspace_auth_key'
#
  def self.get_credentials
    Dir.chdir do
      begin
        Dir.chdir('./.rightscale') do
          require 'test_rackspace_credentials'
        end
      rescue Exception => e
        puts "Couldn't chdir to ~/.rightscale: #{e.message}"
      end
    end
  end

end
