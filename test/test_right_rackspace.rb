# Unit test for Rackspace gem
# Specify your gogrid account credentials as described in test_credentials.rb

require File.dirname(__FILE__) + '/_test_credentials'
require File.dirname(__FILE__) + '/../lib/right_rackspace'

class TestRightRackspace < Test::Unit::TestCase

  TEST_SERVER_NAME = 'right-rackspace-gem-test-server-0123456789'
  TEST_IMAGE_ID  = 8
  TEST_FLAVOR_ID = 2
  TEST_METADATA  = {'key1' => 'value1', 'key2' => 'value2'}
  TEST_PERSONALITIES = { '/home/1.txt' => 'WooHoo', '/home/2.rb' => 'puts "Hello World!"'}

  def setup
    $stdout.sync = true
    ::TestCredentials.get_credentials
    # TODO: remove :auth_endpoint and :service_endpoint when the service is released publicly
    @rackspace = Rightscale::Rackspace::Interface.new(TestCredentials.username, TestCredentials.auth_key,
     :logger => Logger.new('/dev/null'),
     :auth_endpoint    => 'https://api.mosso.com/auth',
     :service_endpoint => 'https://servers.api.rackspacecloud.com/v1.0/413609')
  end

  # -------------
  # Helpers
  # -------------

  def get_test_server_id
    @rackspace.list_servers['servers'].each do |server|
      return server['id'] if server['name'] == TEST_SERVER_NAME
    end
    nil
  end

  def wail_until(reason, &block)
    print reason
    loop do
      print '*'
      sleep 5
      break if block.call
    end
    sleep 10
    puts
  end

  def resources_test(name)
#    puts ">>> Resource test: #{name}"
    resource_type = ''
    name.split('_').each_with_index do |w, i|
      resource_type += (i==0 ? w.downcase : w.capitalize)
    end
    # get resources
    resources = @rackspace.send("list_#{name}")[resource_type]
    # assert the list is an Array
    assert resources.is_a?(Array)
    # assert the custom resource is not an empty Hash
    resource = resources.first
    if resource
      assert  resource.is_a?(Hash)
      assert !resource.blank?
    end

    # get the detailed list of resources
    detailed_resources = @rackspace.send("list_#{name}", :detail => true)[resource_type]
    assert detailed_resources.is_a?(Array)
    # assert the custom detailed resource is not an empty Hash
    detailed_resource = detailed_resources.first
    if detailed_resource
      assert  detailed_resource.is_a?(Hash)
      assert !detailed_resource.blank?
    end

    # make sure the detailed resource contains more data then non detailed
    if resource && detailed_resource
      assert  detailed_resource.size > resource.size
    end

    # Make a custom resource tests
    if resource
      # singularise name (drop a tailing 's')
      name.chop!
      resource_type.chop!
      single_resource = @rackspace.send("get_#{name}", resource['id'])[resource_type]
      assert single_resource.is_a?(Hash)
      assert single_resource['id']
    end
  end

  def right_rackspace_level_caching_test(cache_key, *api_call_data)
#    puts ">>> Rackspace gem level caching test: #{cache_key}"
    # Assert there are no any exceptions while the caching is off
    @rackspace.send(*api_call_data)
    @rackspace.send(*api_call_data)
    # Enable the caching
    @rackspace.params[:caching] = true
    # fill the internal cache with the response
    first_response = @rackspace.send(*api_call_data)
    # make another call and check the cache hit
    assert_raise(Rightscale::Rackspace::NoChange) do
      @rackspace.send(*api_call_data)
    end
    # get the data from the cache and make sure it is equal to the initial call
    assert_equal first_response, @rackspace.cache[cache_key][:data]
    # disable the caching
    @rackspace.params[:caching] = false
  end

  def rackspace_service_level_caching_test(*api_call_data)
#    puts ">>> Rackspace service caching test: #{cache_key}"
    assert_raise(Rightscale::Rackspace::NoChange) do
      opts = api_call_data.last.is_a?(Hash) ? api_call_data.pop : {}
      opts[:vars] = { 'changes-since' => Time.now.utc }
      api_call_data << opts
      @rackspace.send(*api_call_data)
    end
  end

  # -------------
  # Tests
  # -------------

  def test_001_login
    # should fail with a wrong username
    username = @rackspace.username
    @rackspace.username = 'ohohohoho'
    assert_raise Rightscale::Rackspace::Error do
      @rackspace.login
    end
    # should login successfully with the valid username
    @rackspace.username = username
    assert_nothing_raised  do
      @rackspace.login
    end
  end

  def test_003_limits
#    right_rackspace_level_caching_test('/limits', :list_limits)
    limits = nil
    assert_nothing_raised do
      limits = @rackspace.list_limits
    end
    assert limits.is_a?(Hash)
    assert limits['limits'].is_a?(Hash)
    assert limits['limits']['rate'].is_a?(Array)
  end

  def test_005_api_version
    right_rackspace_level_caching_test('/', :list_api_versions)
  end

  def test_010_images
    resources_test('images')
    right_rackspace_level_caching_test('/images', :list_images)
    right_rackspace_level_caching_test('/images/detail', :list_images, :detail => true)
  end

  def test_020_flavors
    resources_test('flavors')
    right_rackspace_level_caching_test('/flavors', :list_flavors)
    right_rackspace_level_caching_test('/flavors/detail', :list_flavors, :detail => true)
    rackspace_service_level_caching_test(:list_flavors)
  end

  def test_030_list_shared_ip_groups
    resources_test('shared_ip_groups')
    right_rackspace_level_caching_test('/shared_ip_groups', :list_shared_ip_groups)
    right_rackspace_level_caching_test('/shared_ip_groups/detail', :list_shared_ip_groups, :detail => true)
    rackspace_service_level_caching_test(:list_shared_ip_groups)
  end

  def test_040_servers
    resources_test('servers')
    right_rackspace_level_caching_test('/servers', :list_servers)
    right_rackspace_level_caching_test('/servers/detail', :list_servers, :detail => true)
    rackspace_service_level_caching_test(:list_servers)
  end

  def test_041_make_sure_the_test_server_is_off
    id = get_test_server_id
    if id
      assert @rackspace.delete_server(id)
      puts ">>> The test server is deleted. "
      sleep 10
    end
  end

  def test_042_create_server
    server = @rackspace.create_server(
      :name          => TEST_SERVER_NAME,
      :image_id      => TEST_IMAGE_ID,
      :flavor_id     => TEST_FLAVOR_ID,
      :metadata      => TEST_METADATA,
      :personalities => TEST_PERSONALITIES
    )
    # wait a while the server is being built
    wail_until('>>> ... waiting while the new test server is being built') do
      @rackspace.get_server(server['server']['id'])['server']['status'] == 'ACTIVE'
    end
    #
    assert server.is_a?(Hash)
    assert_equal TEST_SERVER_NAME, server['server']['name']
    assert_equal TEST_METADATA,    server['server']['metadata']
    assert_equal TEST_IMAGE_ID,    server['server']['imageId']
    assert_equal TEST_FLAVOR_ID,   server['server']['flavorId']
  end

  def test_043_update_server_password
    id = get_test_server_id
    assert @rackspace.update_server(id, :password => '1234567890')
    # wait as bit while the password is being changed
    wail_until('>>> ... waiting while the password is being updated') do
      @rackspace.get_server(id)['server']['status'] == 'ACTIVE'
    end
  end

  def test_044_backup_schedule
    id = get_test_server_id
    # get a schedule
    schedule = nil
    assert_nothing_raised do
      schedule = @rackspace.get_backup_schedule(id)
    end
    assert  schedule['backupSchedule'].is_a?(Hash)
    assert !schedule['backupSchedule']['enabled']
    # Set a new schedule
    assert_nothing_raised do
      assert @rackspace.update_backup_schedule(id, {:enabled => true, :daily => "H_0400_0600", :weekly => 'MONDAY'})
    end
    # delete the schedule
    assert @rackspace.update_backup_schedule(id)
  end

  def test_045_list_addresses_test
    id = get_test_server_id
    # all addresses
    addresses = nil
    assert_nothing_raised do
      addresses = @rackspace.list_addresses(id)
    end
    assert  addresses['addresses'].is_a?(Hash)
    assert  addresses['addresses']['public'].is_a?(Array)
    assert  addresses['addresses']['private'].is_a?(Array)
    # public addresses
    public_addresses = nil
    assert_nothing_raised do
      public_addresses = @rackspace.list_addresses(id, :public)
    end
    assert  public_addresses.is_a?(Hash)
    assert  public_addresses['public'].is_a?(Array)
    assert !public_addresses['public'].blank?
    # private addresses
    private_addresses = nil
    assert_nothing_raised do
      private_addresses = @rackspace.list_addresses(id, :private)
    end
    assert  private_addresses.is_a?(Hash)
    assert  private_addresses['private'].is_a?(Array)
    assert !private_addresses['private'].blank?
  end

  def test_049_delete_server
    assert @rackspace.delete_server(get_test_server_id)
  end

end
