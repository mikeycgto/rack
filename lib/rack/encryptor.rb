# frozen_string_literal: true

require 'openssl'

module Rack
  module Encryptor
    ENCRYPTION_CIPHER     = 'aes-256-gcm'.freeze
    ENCRYPTION_DELIMITER  = '--'.freeze

    def base64_encode(str)
      [str].pack('m0')
    end
    module_function :base64_encode

    def base64_decode(str)
      str.unpack('m0').first
    end
    module_function :base64_decode

    def encrypt_message(data, secret, auth_data = '')
      # TODO raise ArgumentError if data.nil? thus preventing encrypting a nil message
      cipher = OpenSSL::Cipher.new(ENCRYPTION_CIPHER)
      cipher.encrypt
      cipher.key = secret[0, cipher.key_len]

      # Rely on OpenSSL for the initialization vector
      iv = cipher.random_iv

      # This must be set to properly use AES GCM for the OpenSSL module
      cipher.auth_data = auth_data

      cipher_text = cipher.update(data)
      cipher_text << cipher.final

      # TODO code formatting for long string...?
      "#{base64_encode cipher_text}#{ENCRYPTION_DELIMITER}#{base64_encode iv}#{ENCRYPTION_DELIMITER}#{base64_encode cipher.auth_tag}"
    end
    module_function :encrypt_message

    def decrypt_message(data, secret)
      return unless data

      cipher = OpenSSL::Cipher.new(ENCRYPTION_CIPHER)
      cipher_text, iv, auth_tag = data.split(ENCRYPTION_DELIMITER, 3).map! { |v|
        base64_decode(v) }

      # This check is from ActiveSupport::MessageEncryptor
      # see: https://github.com/ruby/openssl/issues/63
      return nil if auth_tag.nil? || auth_tag.bytes.length != 16

      return nil if iv.nil? || iv.empty? # TODO check minimum length?
      return nil if cipher_text.nil? || cipher_text.empty?

      cipher.decrypt
      cipher.key = secret[0, cipher.key_len]
      cipher.iv  = iv
      cipher.auth_tag = auth_tag
      cipher.auth_data = ''

      decrypted_data = cipher.update(cipher_text)
      decrypted_data << cipher.final

      decrypted_data
    rescue OpenSSL::Cipher::CipherError, TypeError, ArgumentError
      nil
    end
    module_function :decrypt_message
  end
end
