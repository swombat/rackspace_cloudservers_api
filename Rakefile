# -*- ruby -*-

require 'rubygems'
require 'hoe'
require "rake/testtask"
require 'rcov/rcovtask'
$: << File.dirname(__FILE__)
require 'lib/right_rackspace.rb'

##testglobs =     ["test/ts_right_aws.rb"]


# Suppress Hoe's self-inclusion as a dependency for our Gem.  This also keeps
# Rake & rubyforge out of the dependency list.  Users must manually install
# these gems to run tests, etc.
class Hoe
  def extra_deps
    @extra_deps.reject do |x|
      Array(x).first == 'hoe'
    end
  end
end

Hoe.new('right_rackspace', RightRackspace::VERSION::STRING) do |p|
  p.rubyforge_name = 'rightrackspace'
  p.author = 'RightScale, Inc.'
  p.email = 'support@rightscale.com'
  p.summary = 'Interface classes for the Rackspace Services'
##  p.description = p.paragraphs_of('README.txt', 2..5).join("\n\n")
##  p.url = p.paragraphs_of('README.txt', 0).first.split(/\n/)[1..-1]
##  p.changes = p.paragraphs_of('History.txt', 0..1).join("\n\n")
##  p.remote_rdoc_dir = "/right_rackspace_gem_doc"
  p.extra_deps = [['right_http_connection','>= 1.2.1']]
##  p.test_globs = testglobs
end

##desc "Analyze code coverage of the unit tests."
##Rcov::RcovTask.new do |t|
##  t.test_files = FileList[testglobs]
##  #t.verbose = true     # uncomment to see the executed command
##end
 
# vim: syntax=Ruby
