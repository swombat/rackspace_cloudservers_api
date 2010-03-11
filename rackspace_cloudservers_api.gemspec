# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{rackspace_cloudservers_api}
  s.version = "0.0.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Daniel Tenner", "Rightscale"]
  s.date = %q{2010-03-11}
  s.description = %q{CloudServers Api based on RightScale's gem}
  s.email = %q{daniel.gemcutter@tenner.org}
  s.extra_rdoc_files = [
    "README.txt"
  ]
  s.files = [
    ".gitignore",
     "History.txt",
     "Manifest.txt",
     "README.txt",
     "Rakefile",
     "VERSION",
     "lib/benchmark_fix.rb",
     "lib/rackspace.rb",
     "lib/rackspace_base.rb",
     "lib/right_rackspace.rb",
     "lib/support.rb",
     "test/_test_credentials.rb",
     "test/test_right_rackspace.rb"
  ]
  s.homepage = %q{http://github.com/swombat/rackspace_cloudservers_api}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{CloudServers Api based on RightScale's gem}
  s.test_files = [
    "test/_test_credentials.rb",
     "test/test_right_rackspace.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
