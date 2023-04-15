require 'openssl'
require 'digest/sha2'
require 'securerandom'
require 'base64'
require 'stringio'

# Stay in our own namespace
module WIKK
  # Provides AES 256 Encryption, as well as generation of keys and initial vectors, which could be used in other places.
  #
  # @attr_reader [String] plain_text the decrypted text
  # @attr_reader [String] cipher_text the encrypted text
  class AES_256
    VERSION = '0.1.8'
    AES_256_CBC = 'AES-256-CBC'

    attr_reader :plain_text, :cipher_text

    # Initialize
    #
    # @param key_string [String] optional base64 key to be used in encryption or decryption.
    #    if nil, then key and iv are generated automatically. Recover the key with key_to_s(), or key_iv_to_s()
    # @param iv_string [String ] optional base64 iv (initial vector) to be used in the encryption or decryption
    #    Overwritten by auto generated iv, if key_string is nil. Recover with iv_to_str() or key_iv_to_s().
    def initialize(key_string = nil, iv_string = nil)
      if key_string.nil?
        gen_key
      else
        str_to_key(key_string)
      end

      if iv_string.nil?
        gen_iv
      else
        str_to_iv(iv_string)
      end
    end

    # Generates a new binary key in @key, using SecureRandom.
    #
    # @return [String] Binary string, @key
    def gen_key(key_length = 32)
      @key = SecureRandom.gen_random(key_length)
    end

    # Convert key to a base64 string
    #
    # @return [String] base64 version of @key
    def key_to_s
      return [ @key ].pack('m').chomp
    end

    # Convert a base64 string into a key
    #
    # @param [String] converts base64 version of key into AES_256_CBC Symetric Key.
    # @return [String] Binary string, @key
    def str_to_key(base64_keystring)
      return( @key = base64_keystring.unpack1('m') )
    end

    # Generate random AES_256_CBC initialization vector.
    #
    # @return [String] Binary initialization vector @iv
    def gen_iv
      return (@iv = OpenSSL::Cipher.new(AES_256_CBC).random_iv)
    end

    # Convert initialization vector to base64 string
    #
    # @return [String] return Base64 version of initialization vector @iv
    def iv_to_s
      return [ @iv ].pack('m').chomp
    end

    # Convert base64 string into an initialization vector
    #
    # @param [String] turns base64 version of iv into AES_256_CBC initialization vector.
    # @return [Array] AES_256_CBC initialization vector @iv.
    def str_to_iv(base64_iv_string)
      return (@iv = base64_iv_string.unpack1('m'))
    end

    # Convert key and the initialization vector into base64 strings
    #
    # @return [String,String] base64 version of @key;
    #                         Base64 version of initialization vector @iv
    def key_iv_to_s
      return key_to_s, iv_to_s
    end

    # Encrypts source using AES 256 CBC, using @key and @iv
    #
    # @param unencrypted_source [String|File]
    # @return [String] Binary string representing encrypted source
    def encrypt(unencrypted_source)
      unencrypted_source = StringIO.new(unencrypted_source) if unencrypted_source.instance_of?(String)
      aes = OpenSSL::Cipher.new(AES_256_CBC)
      aes.encrypt
      aes.key = @key
      aes.iv = @iv
      @cipher_text = ''
      while (s = unencrypted_source.read(4096)) != nil do @cipher_text << aes.update(s); end
      @cipher_text << aes.final
    end

    # Converts encrypted source String, @cipher_text, into Base64 String
    #
    # @param unencrypted_source [String|File] If present, then this source is encrypted, otherwise assumes already encrypted.
    # @return [String] Base64 string representing encrypted source
    def cipher_to_s(unencrypted_source = nil)
      encrypt(unencrypted_source) if unencrypted_source != nil
      return [ @cipher_text ].pack('m').chomp
    end

    # Decrypts source using AES 256 CBC, using @key and @iv
    #
    # @param encrypted_source [String|File]
    # @param base64_source [Boolean] if true, then source is assumed to be base64 encoded.
    # @return [String] String representing the original unencypted source
    def decrypt(encrypted_source, base64_source = false)
      encrypted_source = StringIO.new(encrypted_source) if encrypted_source.instance_of?(String)
      read_count = base64_source ? 5464 : 4096
      decode_cipher = OpenSSL::Cipher.new(AES_256_CBC)
      decode_cipher.decrypt
      decode_cipher.key = @key
      decode_cipher.iv = @iv
      @plain_text = ''
      while (et = encrypted_source.read(read_count)) != nil
        @plain_text << (base64_source ? decode_cipher.update(et.unpack1('m')) : decode_cipher.update(et))
      end
      @plain_text << decode_cipher.final
    end

    # Generates a random base64 key.
    #
    # @return [String] Base64 encoded string, @key
    def self.gen_key_to_s(key_length = 32)
      SecureRandom.base64(key_length)
    end

    # Generate random AES_256_CBC initialization vector.
    #
    # @return [String] Base64 encoded initialization vector @iv
    def self.gen_iv_to_s
      return [ OpenSSL::Cipher.new(AES_256_CBC).random_iv ].pack('m').chomp
    end

    # Generates a new key using Random string in @key, and random AES_256_CBC initialization vector in @iv
    #
    # @return [String,String] Base64 encoded string, @key;
    #                  Base64 encoded initialization vector @iv
    def self.gen_key_iv_to_s
      return self.gen_key_to_s, self.gen_iv_to_s
    end

    # Encrypts source using AES 256 CBC, using @key and @iv
    #
    # @param unencrypted_source [String|File]
    # @param key_string [String] optional base64 key to be used in encryption or decryption.
    #    if nil, then key and iv are generated automatically. Recover the key with key_to_s(), or key_iv_to_s()
    # @param iv_string [String ] optional base64 iv (initial vector) to be used in the encryption or decryption
    #    Overwritten by auto generated iv, if key_string is nil. Recover with iv_to_str() or key_iv_to_s().
    # @return [String,String,String] Binary string representing encrypted source;
    #                                base64 key, @key, so later decryption can be done;
    #                                base64 initial vector, @iv, so later decryption can be done
    def self.encrypt(unencrypted_source, key_string = nil, iv_string = nil)
      aes = self.new(key_string, iv_string)
      return aes.encrypt(unencrypted_source), aes.key_to_s, aes.iv_to_s
    end

    # Converts encrypted source String, @cipher_text, into Base64 String
    #
    # @param unencrypted_source [String|File] which must be present, as AES_256 class is created here.
    # @param key_string [String] optional base64 key to be used in encryption or decryption.
    #    if nil, then key and iv are generated automatically. Recover the key with key_to_s(), or key_iv_to_s()
    # @param iv_string [String ] optional base64 iv (initial vector) to be used in the encryption or decryption
    #    Overwritten by auto generated iv, if key_string is nil. Recover with iv_to_str() or key_iv_to_s().
    # @return [String,String,String] Base64 string representing encrypted source;
    #                                base64 key, @key, so later decryption can be done;
    #                                base64 initial vector, @iv, so later decryption can be done
    def self.cipher_to_s(unencrypted_source, key_string = nil, iv_string = nil)
      aes = self.new(key_string, iv_string)
      return aes.cipher_to_s(unencrypted_source), aes.key_to_s, aes.iv_to_s
    end

    # Creates an AES class and then Decrypts source using AES 256 CBC, using @key and @iv
    #
    # @param encrypted_source [String|File]
    # @param base64_source [Boolean] if true, then source is assumed to be base64 encoded.
    # @param key_string [String] optional base64 key to be used in encryption or decryption.
    #    if nil, then key and iv are generated automatically. Recover the key with key_to_s(), or key_iv_to_s()
    # @param iv_string [String ] optional base64 iv (initial vector) to be used in the encryption or decryption
    #    Overwritten by auto generated iv, if key_string is nil. Recover with iv_to_str() or key_iv_to_s().
    # @return [String] String representing the original unencypted source
    def self.decrypt(encrypted_source, base64_source = false, key_string = nil, iv_string = nil)
      aes = self.new(key_string, iv_string)
      return aes.decrypt(encrypted_source, base64_source)
    end
  end
end
