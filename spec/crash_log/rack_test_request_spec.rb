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
    Delorean.time_travel_to(Date.parse("Thu, 10 Jul 2008 03:29:56 GMT"))

    env = current_session.__send__(:env_for, '/notify', {}.merge(:method => "POST", :params => {token: 'my-key-id'}))
    signature = CrashLog::AuthHMAC.sign!(env, "my-key-id", "secret")
    signature.should == "AuthHMAC my-key-id:nt0VFUekBB3Ci5cCyaqy9fQnaK0="
  end
end
