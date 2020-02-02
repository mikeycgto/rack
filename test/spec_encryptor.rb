# frozen_string_literal: true

require 'minitest/autorun'
require 'rack/encryptor'
require 'rack/utils'

describe Rack::Encryptor do
  def setup
    @secret = OpenSSL::Cipher.new(Rack::Encryptor::ENCRYPTION_CIPHER).random_key
  end

  it 'encrypted message contains ciphertext iv and auth_tag' do
    msg = Rack::Encryptor.encrypt_message('hello world', @secret)

    ctxt, iv, auth_tag = msg.split(Rack::Encryptor::ENCRYPTION_DELIMITER, 3)

    ctxt.wont_be :empty?
    iv.wont_be :empty?
    auth_tag.wont_be :empty?
  end

  it 'encrypted message is decryptable' do
    cmsg = Rack::Encryptor.encrypt_message('hello world', @secret)
    pmsg = Rack::Encryptor.decrypt_message(cmsg, @secret)

    pmsg.must_equal 'hello world'
  end

  it 'encryptor and decryptor handles overly long keys' do
    new_secret = "#{@secret}abcdef123456"

    # These methods should truncate the long key (so OpenSSL raises an exception)
    cmsg = Rack::Encryptor.encrypt_message('hello world', new_secret)
    pmsg = Rack::Encryptor.decrypt_message(cmsg, new_secret)

    pmsg.must_equal 'hello world'
  end

  it 'decrypt returns nil for junk messages' do
    Rack::Encryptor.decrypt_message('aaa--bbb-ccc', @secret).must_be_nil
  end

  it 'decrypt returns nil for tampered messages' do
    cmsg = Rack::Encryptor.encrypt_message('hello world', @secret)

    csplit = cmsg.split(Rack::Encryptor::ENCRYPTION_DELIMITER, 3)
    csplit[2] = csplit.last.reverse

    tampered_msg = csplit.join(Rack::Encryptor::ENCRYPTION_DELIMITER)

    Rack::Encryptor.decrypt_message(tampered_msg, @secret).must_be_nil
  end
end
