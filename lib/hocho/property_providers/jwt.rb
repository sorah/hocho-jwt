require 'erb'
require 'jwt'
require 'openssl'

require 'hocho/property_providers/base'

module Hocho
  module PropertyProviders
    class Jwt < Base
      def initialize(algorithm:, signing_key:, sub_template:)
        @algorithm = algorithm
        @signing_key = load_key(**(signing_key || {}))
        @sub_template = Class.new(Template).tap { |t| t.erb = ERB.new(sub_template) }
      end

      def determine(host)
        request = Request.new(**{
          issue: false,
          claims: {},
          fail_when_no_signing_key: true,
        }.merge(host.properties[:hocho_jwt] || {}))

        return unless host.properties.dig(:hocho_jwt, :issue)

        unless @signing_key
          if request.fail_when_no_signing_key
            raise ArgumentError, "cannot issue JWT key, no signing key is present"
          else
            return
          end
        end

        host.attributes[:hocho_jwt] = {
          token: JWT.encode(
            payload(request, host),
            @signing_key,
            @algorithm,
          ),
        }

        nil
      end

      private

      class Template
        def self.erb; @erb; end
        def self.erb=(x); @erb = x; end

        def initialize(host)
          @host = host
        end

        attr_reader :host

        def result()
          self.class.erb.result(binding)
        end
      end


      Request = Struct.new(:issue, :duration, :claims, :fail_when_no_signing_key, keyword_init: true)

      def payload(request, host)
        now = Time.now
        data = {
          sub: @sub_template.new(host).result(),
        }
        data[:iat] = now.to_i
        if request.duration
          data[:nbf] = now.to_i
          data[:exp] = (now + request.duration).to_i
        end
        data.merge(request.claims)
      end

      def load_key(pem_string: nil, pem_file: nil, pem_env: nil)
        pem = case
        when pem_string
          pem_string.to_s
        when pem_file
          File.read(pem_string) rescue nil
        when pem_env
          ENV[pem_env].yield_self do |e|
            if e.start_with?('-----')
              e
            else
              e.unpack1('m*')
            end
          end
        end
        return nil unless pem

        case @algorithm
        when /^ES/
          OpenSSL::PKey::EC.new(pem, '')
        when /^RS/
          OpenSSL::PKey::RSA.new(pem, '')
        else
          raise ArgumentError, "unsupported cipher algorithm"
        end
      end
    end
  end
end
