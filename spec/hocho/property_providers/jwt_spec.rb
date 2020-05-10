require 'spec_helper'
require 'hocho/property_providers/jwt'

RSpec.describe Hocho::PropertyProviders::Jwt do
  KEY = OpenSSL::PKey::EC.generate('prime256v1').tap(&:generate_key)
  PUBLIC_KEY = OpenSSL::PKey::EC.new(KEY).tap { |_|  _.private_key = nil }

  let(:host_properties) { { hocho_jwt: properties } }
  let(:properties) { nil }

  let(:host) do
    double(:host, properties: host_properties, name: 'hostname', attributes: {})
  end

  let(:signing_key) { { pem_string: KEY.to_pem } }

  subject(:provider) {
    described_class.new(
      signing_key: signing_key,
      algorithm: 'ES256',
      sub_template: '<%= host.name %>',
    )
  }

  describe "#determine" do
    describe "issue=false" do
      it "does nothing" do
        provider.determine(host)
        expect(host.attributes[:hocho_jwt]).to be_nil
      end
    end

    describe "issue=true" do
      let(:properties) { { issue: true, claims: { aud: 'test' } }  }
      let(:now) { Time.now }

      subject(:decoded_jwt) do
        JWT.decode(
          host.attributes.dig(:hocho_jwt, :token).to_s,
          PUBLIC_KEY,
          true,
          algorithm: 'ES256',
        )
      end

      subject(:jwt_header) do
        decoded_jwt[1]
      end

      subject do
        decoded_jwt[0]
      end

      before do
        allow(Time).to receive(:now).and_return(now)
      end

      it "issues JWT" do
        provider.determine(host)
        expect(subject['sub']).to eq('hostname')
        expect(subject['iat']).to eq(now.to_i)
        expect(subject['aud']).to eq('test')
      end

      describe "duration" do
        let(:properties) { { issue: true, duration: 120 } }

        it "issues JWT with expiration" do
          provider.determine(host)
          expect(subject['nbf']).to eq(now.to_i)
          expect(subject['iat']).to eq(now.to_i)
          expect(subject['exp']).to eq(now.to_i + 120)
        end
      end


      describe "kid" do
        let(:signing_key) { { pem_string: KEY.to_pem, kid_string: 'keyid' } }

        it "issues JWT with kid" do
          provider.determine(host)
          expect(jwt_header['kid']).to eq('keyid')
        end
      end



      describe "fail_when_no_signing_key=false" do
        let(:properties) { { issue: true, fail_when_no_signing_key: false} }
        let(:signing_key) { nil }

        it "does nothing" do
          provider.determine(host)
          expect(host.attributes[:hocho_jwt]).to be_nil
        end
      end

      describe "fail_when_no_signing_key=true" do
        let(:properties) { { issue: true, fail_when_no_signing_key: true} }
        let(:signing_key) { nil }

        it "does nothing" do
          expect {
            provider.determine(host)
          }.to raise_error(ArgumentError)
        end
      end
    end
  end
end
