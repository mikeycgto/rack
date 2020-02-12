# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'
require 'zlib'

module Rack
  class Encryptor
    class Error < StandardError
    end

    class InvalidSignature < Error
    end

    class InvalidMessage < Error
    end

    DEFLATE_BIT = 0x1000

    # The secret String must be at least 64 bytes in size. The first 32 bytes
    # will be used for the encryption cipher key. The remainder will be used
    # for an HMAC key.
    #
    # Options may include:
    # * :serialize_json
    #     Use JSON for message serialization instead of Marshal. This can be
    #     viewed as a security ehancement.
    # * :gzip_over
    #     For message data over this many bytes, compress it with the deflate
    #     algorithm.
    # * :purpose
    #     Limit messages to a specific purpose. This can be viewed as a
    #     security enhancement to prevent message reuse from different contexts
    #     if keys are reused.
    #
    # Cryptography and Output Format:
    #
    #   urlsafe_encode64(version + random_data + IV + encrypted data + HMAC)
    #
    #  Where:
    #  * version - 1 byte and is currently always 0x01
    #  * random_data - 32 bytes used for generating the per-message secret
    #  * IV - 16 bytes random initialization vector
    #  * HMAC - 32 bytes HMAC-SHA-256 of all preceding data, plus the purpose value
    def initialize(secret, opts = {})
      raise ArgumentError, "secret must be a String" unless String === secret
      raise ArgumentError, "invalid secret: #{secret.bytesize}, must be >=64" unless secret.bytesize >= 64

      @options = {
        serialize_json: false, gzip_over: nil, purpose: nil
      }.update(opts)

      @hmac_secret = secret.dup.force_encoding('BINARY')
      @cipher_secret = @hmac_secret.slice!(0, 32)

      @hmac_secret.freeze
      @cipher_secret.freeze
    end

    def decrypt(base64_data)
      data = Base64.urlsafe_decode64(base64_data)

      signature = data.slice!(-32..-1)

      verify_authenticity! data, signature

      _version = data.slice!(0, 1)
      cipher_secret = data.slice!(0, 32)
      cipher_iv = data.slice!(0, 16)

      cipher = new_ciper
      cipher.decrypt
      cipher.key = cipher_secret
      cipher.iv = cipher_iv
      data = cipher.update(data) << cipher.final

      deserialized_data data
    rescue ArgumentError
      raise InvalidSignature, 'Message invalid'
    end

    def encrypt(message)
      version = "\1"

      serialized_payload = serialize_payload(message)
      message_secret, cipher_secret = new_message_and_cipher_secret

      cipher = new_ciper
      cipher.encrypt
      cipher.key = cipher_secret
      cipher_iv = cipher.random_iv

      encrypted_data = cipher.update(serialized_payload) << cipher.final

      data = String.new
      data << version
      data << cipher_secret
      data << cipher_iv
      data << encrypted_data
      data << compute_signature(data)

      Base64.urlsafe_encode64(data)
    end

    private

    def new_ciper
      OpenSSL::Cipher.new('aes-256-ctr')
    end

    def new_message_and_cipher_secret
      message_secret = SecureRandom.random_bytes(32)
      cipher_secret = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @cipher_secret, message_secret)

      [message_secret, cipher_secret]
    end

    def serializer
      @serializer ||= @options[:serialize_json] ? JSON : Marshal
    end

    def compute_signature(data)
      signing_data = data
      signing_data += @options[:purpose] if @options[:purpose]

      OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @hmac_secret, signing_data)
    end

    def verify_authenticity!(data, signature)
      raise InvalidMessage, 'Message is invalid' if data.nil? || signature.nil?

      unless Rack::Utils.secure_compare(signature, compute_signature(data))
        raise InvalidSignature, 'HMAC is invalid'
      end
    end

    # Returns a serialized payload that includes the serialized message and a
    # set of encoding options stored in a bitmap.
    #
    # Currently, the bitmap is 2 bytes in size.
    def serialize_payload(message)
      serialized_data = serializer.dump(message)

      bitmap = 0

      if !@options[:gzip_over].nil? && serialized_data.size > @options[:gzip_over]
        serialized_data = Zlib.deflate(serialized_data)

        bitmap |= DEFLATE_BIT
      end

      "#{[bitmap].pack('v')}#{serialized_data}"
    end

    def deserialized_data(serialized_data)
      bitmap, = serialized_data.slice!(0, 2).unpack('v')

      if bitmap & DEFLATE_BIT > 0
        serialized_data = Zlib::Inflate.inflate(serialized_data)
      end

      serializer.load(serialized_data)
    end
  end
end
