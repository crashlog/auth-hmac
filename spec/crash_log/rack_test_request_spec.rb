require 'spec_helper'
require "net/http"
require 'time'
require 'active_support'
require 'rack/test'
require "delorean"

describe CrashLog::AuthHMAC do
  include Rack::Test::Methods

  def app
    lambda do |env|
      [200, {"Content-Type" => "text/html", "Content-Length" => 13}, "Hello, World!"]
    end
  end

  it 'says hello world' do
    get '/'
    last_response.status.should == 200
    last_response.body.should == 'Hello, World!'
  end

  it 'can process rack test requests' do
    # HMAC uses date to validate request signature, we need to fix the date so
    # that it matches.
    Delorean.time_travel_to(Time.utc(2008,7,10,3,29,56))

    env = current_session.__send__(:env_for, '/notify', {:method => "POST", 'CONTENT_TYPE' => "text/plain"})
    puts env.inspect
    signature = CrashLog::AuthHMAC.sign!(env, "my-key-id", "secret")
    signature.should == "AuthHMAC my-key-id:nt0VFUekBB3Ci5cCyaqy9fQnaK0="
  end

  it 'can handle hash requests' do
    Delorean.time_travel_to(Date.parse("Thu, 10 Jul 2008 03:29:56 GMT"))

    request_hash = {
      'REQUEST_METHOD' => 'PUT',
      'content-type' => 'text/plain',
      'content-md5' => 'blahblah',
      'date' => "Thu, 10 Jul 2008 03:29:56 GMT",
      'PATH_INFO' => '/notify'
    }

    standard_request = Net::HTTP::Put.new("/notify",
      'content-type' => 'text/plain',
      'content-md5' => 'blahblah',
      'date' => "Thu, 10 Jul 2008 03:29:56 GMT")

    sig = CrashLog::AuthHMAC.signature(request_hash, 'secret')
    sig.should == CrashLog::AuthHMAC.signature(standard_request, 'secret')
  end

  it 'accepts real request without content md5' do
    Delorean.time_travel_to(Date.parse("Thu, 04 Oct 2012 08:31:16 GMT"))

    request = Net::HTTP::Post.new("/events",
      'content-type' => 'application/json; charset=UTF-8',
      'date' => "Thu, 04 Oct 2012 08:31:16 GMT")

    sig = CrashLog::AuthHMAC.signature(request, '2Xbz25UpU8nQxaSAKuixJQMDxuiqryxzArzSJJ8Ci3Mr')
    sig.should == 'Rqj0DdG4/jNrzOXdybz13CaKzXU='
  end

end
