# frozen_string_literal: true

require 'json'
require 'zlib'

# JWT::Encode module
module JWT
  # Encoding logic for JWT
  class Encode
    attr_reader :payload, :key, :algorithm, :header_fields, :segments

    def self.base64url_encode(str, algorithm: nil)
      str = compress(str) if algorithm == 'ED255'
      Base64.encode64(str).tr('+/', '-_').gsub(/[\n=]/, '')
    end

    def self.compress(str)
      zlib = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
      zlib.deflate(str)
      zlib.finish
    end

    def initialize(payload, key, algorithm, header_fields)
      @payload = payload
      @key = key
      @algorithm = algorithm
      @header_fields = header_fields
      @segments = encode_segments
    end

    private

    def encoded_header(algorithm, header_fields)
      header = { 'alg' => algorithm }.merge(header_fields)
      Encode.base64url_encode(JSON.generate(header), algorithm: algorithm)
    end

    def encoded_payload(payload)
      raise InvalidPayload, 'exp claim must be an integer' if payload && payload['exp'] && !payload['exp'].is_a?(Integer)
      Encode.base64url_encode(JSON.generate(payload), algorithm: algorithm)
    end

    def encoded_signature(signing_input, key, algorithm)
      if algorithm == 'none'
        ''
      else
        signature = JWT::Signature.sign(algorithm, signing_input, key)
        Encode.base64url_encode(signature, algorithm: algorithm)
      end
    end

    def encode_segments
      segments = []
      segments << encoded_header(@algorithm, @header_fields)
      segments << encoded_payload(@payload)
      segments << encoded_signature(segments.join('.'), @key, @algorithm)
      segments.join('.')
    end
  end
end
