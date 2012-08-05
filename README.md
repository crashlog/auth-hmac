# Crashlog::AuthHMAC

[![Build Status](https://secure.travis-ci.org/crashlog/auth-hmac.png?branch=master)](http://travis-ci.org/crashlog/auth-hmac)

auth-hmac is a Ruby implementation of HMAC based authentication of HTTP requests.

HMAC authentication involves a client and server having a shared secret key. When sending the request the client, signs the request using the secret key. This involves building a canonical representation of the request and then generating a HMAC of the request using the secret. The generated HMAC is then sent as part of the request.

When the server receives the request it builds the same canonical representation and generates a HMAC using it’s copy of the secret key, if the HMAC produced by the server matches the HMAC sent by the client, the server can be assured that the client also possesses the shared secret key.

HMAC based authentication also provides message integrity checking because the HMAC is based on a combination of the shared secret and the content of the request. So if any part of the request that is used to build the canonical representation is modified by a malicious party or in transit the authentication will then fail.

AuthHMAC was built to support authentication between various applications build by Peerworks.

AuthHMAC is loosely based on the Amazon Web Services authentication scheme but without the Amazon specific components, i.e. it is HMAC for the rest of us.


### Legacy note:

This gem is based largely on the original `auth-hmac` gem by Sean Geoghegan, however
we have removed the Rails support as we use it exclusively within our CrashLog Ruby Gem
which must maintain compatibility with many versions of Rails.

## Installation

Add this line to your application's Gemfile:

    gem 'crashlog-auth-hmac'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install crashlog-auth-hmac

## Usage

The simplest way to use AuthHMAC is with the `CrashLog::AuthHMAC.sign!` and
`CrashLog::AuthHMAC#authenticate?` methods.

`CrashLog::AuthHMAC.sign!` takes a HTTP request object, an access id and a secret key and signs the request with the access_id and secret key.

The HTTP request object can be a Net::HTTP::HTTPRequest object, a CGI::Request object or a Webrick HTTP request object. AuthHMAC will do its best to figure out which type it is an handle it accordingly.

The access_id is used to identify the secret key that was used to sign the request. Think of it as like a user name, it allows you to hand out different keys to different clients and authenticate each of them individually. The access_id is sent in the clear so you should avoid making it an important string.

The secret key is the shared secret between the client and the server. You should make this sufficiently random so that is can’t be guessed or exposed to dictionary attacks. The follow code will give you a pretty good secret key:

random = File.read(‘/dev/random’, 512) secret_key = Base64.encode64(Digest::SHA2.new(512).digest(random)) On the server side you can then authenticate these requests using the AuthHMAC.authenticated? method. This takes the same arguments as the sign! method but returns true if the request has been signed with the access id and secret	or false if it hasn’t.

If you have more than one set of credentials you might find it useful to create an instance of the AuthHMAC class, passing your credentials as a Hash of access id => secret keys, like so:

@authhmac = AuthHMAC.new(‘access_id1’ => ‘secret1’, ‘access_id2’ => ‘secret2’) You can then use the instance methods of the @authhmac object to sign and authenticate requests, for example:

@authhmac.sign!(request, “access_id1”) will sign request with “access_id1” and it’s corresponding secret key. Similarly authentication is done like so:

@authhmac.authenticated?(request)
which will return true if the request has been signed with one of the access id and secret key pairs provided in the constructor.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## Contributors

- This gem is based on the [original work by Sean Geoghegan](https://github.com/seangeo/auth-hmac)
- Ivan Vanderbyl

