# frozen_string_literal: true

require_relative 'helper'
require 'rack/encryptor'
require 'rack/utils'

describe Rack::Encryptor do
  def setup
    @secret = SecureRandom.random_bytes(64)
  end

  it 'initialize does not destroy key string' do
    encryptor = Rack::Encryptor.new(@secret)

    @secret.size.must_equal 64
  end

  it 'decrypts an encrypted message' do
    encryptor = Rack::Encryptor.new(@secret)

    message = encryptor.encrypt(foo: 'bar')

    encryptor.decrypt(message).must_equal foo: 'bar'
  end

  it 'decrypt raises InvalidSignature for tampered messages' do
    encryptor = Rack::Encryptor.new(@secret)

    message = encryptor.encrypt(foo: 'bar')

    decoded_message = Base64.urlsafe_decode64(message)
    tampered_message = Base64.urlsafe_encode64(decoded_message.tap { |m|
      m[m.size - 1] = "\0"
    })

    lambda {
      encryptor.decrypt(tampered_message)
    }.must_raise Rack::Encryptor::InvalidSignature
  end

  it 'decrypts an encrypted message with gzip' do
    encryptor = Rack::Encryptor.new(@secret, gzip_over: 1)

    message = encryptor.encrypt(foo: 'bar')

    encryptor.decrypt(message).must_equal foo: 'bar'
  end

  it 'encryptor with gzip reduces size on large messages' do
    encryptor_without = Rack::Encryptor.new(@secret)
    encryptor_with = Rack::Encryptor.new(@secret, gzip_over: 1)

    message_without = encryptor_without.encrypt('A' * 1000)
    message_with = encryptor_with.encrypt('A' * 1000)

    # gzipped version is at least 4 times smaller
    (message_with.size * 4).must_be :<, message_without.size
  end

  it 'decrypts an encrypted message with purpose' do
    encryptor = Rack::Encryptor.new(@secret, purpose: 'testing')

    message = encryptor.encrypt(foo: 'bar')

    encryptor.decrypt(message).must_equal foo: 'bar'
  end

  it 'decrypts raises InvalidSignature without purpose' do
    encryptor = Rack::Encryptor.new(@secret, purpose: 'testing')
    other_encryptor = Rack::Encryptor.new(@secret)

    message = other_encryptor.encrypt(foo: 'bar')

    lambda { encryptor.decrypt(message) }.must_raise Rack::Encryptor::InvalidSignature
  end

  it 'decrypts raises InvalidSignature with different purpose' do
    encryptor = Rack::Encryptor.new(@secret, purpose: 'testing')
    other_encryptor = Rack::Encryptor.new(@secret, purpose: 'other')

    message = other_encryptor.encrypt(foo: 'bar')

    lambda { encryptor.decrypt(message) }.must_raise Rack::Encryptor::InvalidSignature
  end
end
