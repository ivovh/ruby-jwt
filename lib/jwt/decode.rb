# frozen_string_literal: true

require 'json'
require 'zlib'

# JWT::Decode module
module JWT
  # Decoding logic for JWT
  class Decode
    attr_reader :header, :payload, :signature

    def self.base64url_decode(str, algorithm: nil)
      str += '=' * (4 - str.length.modulo(4))
      output = Base64.decode64(str.tr('-_', '+/'))
      output = decompress(output) if algorithm == 'ED255'
      output
    end

    def self.decompress(str)
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(str)
    end

    def initialize(jwt, verify, algorithm: nil)
      @jwt = jwt
      @verify = verify
      @algorithm = algorithm
      @header = ''
      @payload = ''
      @signature = ''
    end

    def decode_segments
      header_segment, payload_segment, crypto_segment = raw_segments
      @header, @payload = decode_header_and_payload(header_segment, payload_segment)
      @signature = Decode.base64url_decode(crypto_segment.to_s, algorithm: @algorithm) if @verify
      signing_input = [header_segment, payload_segment].join('.')
      [@header, @payload, @signature, signing_input]
    end

    private

    def raw_segments
      segments = @jwt.split('.')
      required_num_segments = @verify ? [3] : [2, 3]
      raise(JWT::DecodeError, 'Not enough or too many segments') unless required_num_segments.include? segments.length
      segments
    end

    def decode_header_and_payload(header_segment, payload_segment)
      header = JSON.parse(Decode.base64url_decode(header_segment, algorithm: @algorithm))
      payload = JSON.parse(Decode.base64url_decode(payload_segment, algorithm: @algorithm))
      [header, payload]
    rescue JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  end
end
