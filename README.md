# hocho-jwt: Pass JWT to servers on `hocho apply`

[hocho](https://github.com/sorah/hocho) plugin to issue and sign JWT (JSON Web Token) and pass it to a host as a node attribute on `hocho apply`.

## Use cases

- Use with step-ca ([smallstep/certificates](https://github.com/smallstep/certificates)): allow servers to get certificates from step-ca during initial provision with hocho

## Installation

Add this line to your Gemfile:

```ruby
gem 'hocho-jwt'
```

## Usage

```yaml
# hocho.yml
property_providers:
  - add_default:
      properties:
        hocho_jwt:
          ## JWT will be issued when host.properties.jwt.issue is present
          issue: false

          ## Lifetime in seconds
          duration: 120

          ## Claims
          claims:
            iss: hocho
          
          ## Set false to skip when issue=true but no signing key is present.
          fail_when_no_signing_key: true
  - jwt:
      algorithm: ES256

      ## Signing Private Key
      # EC256: openssl ecparam -name prime256v1 -genkey -noout -out key.pem
      # RS256: openssl genrsa -noout -out key.pem 2048
      signing_key:
        ## Key ID
        # kid_string: key-id
        # kid_file: path/to/kid
        # kid_env: HOCHO_JWT_KID
        ## String to PEM or Base64 encoded DER
        # pem_string: "..."
        # pem_file: /path/to/jwk
        # pem_env: HOCHO_JWT_KEY

      ## Templates are rendered using ERB, and `host` (Hocho::Host) is given. 
      ## Invalid DNS names will be removed.
      sub_template: "<%= host.name %>"
```

```yaml
# hocho host.yml
myhost.example.org:
  properties:
    hocho_jwt:
      issue: true
      claims:
        # this overrides sub_template
        # sub: "static-subject.example.org"
        aud: 'audience'
        customclaim: test
        customclaimarray: ['test']
        
```

```ruby
# itamae recipe

file "/etc/jwt.txt" do
  content "#{node[:hocho_jwt][:token]}\n"
  owner 'root'
  group 'root'
  mode  '0640'
end

execute "do-something-with-token"
```


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/hocho-jwt.


## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
