module WIKK
  require "openssl"
  require 'digest/sha2'
  require 'base64'

  #Provides AES 256 Encryption, as well as generation of keys and initial vectors, which could be used in other places.
  # @attr_reader [String] plain_text the decrypted text
  # @attr_reader [String] cipher_text the encrypted text
  class AES_256
    VERSION = "0.1.1"
    AES_256_CBC = "AES-256-CBC"
    
    attr_reader :plain_text, :cipher_text
    
    #Initialize
    #  @param key_string [String] optional base64 key to be used in encryption or decryption. 
    #    if nil, then key and iv are generated automatically. Recover the key with key_to_s(), or key_iv_to_s()
    #  @param iv_string [String ] optional base64 iv (initial vector) to be used in the encryption or decryption
    #    Overwritten by auto generated iv, if key_string is nil. Recover with iv_to_str() or key_iv_to_s().
    def initialize(key_string = nil, iv_string = nil)
      if(key_string == nil)
        gen_key
        gen_iv
      else
        str_to_key(key_string)
        str_to_iv(iv_string)
      end
    end
    
    #Generates a new key using Digest SHA256 in @key.
    #  @return [String] Binary string, @key
  	def gen_key
      digest = Digest::SHA256.new
      digest.update("symetric key")
      return (@key = digest.digest)
    end
    
    #  @return [String] base64 version of @key
    def key_to_s
      return [@key].pack('m').chomp
    end

    #  @param [String] turns base64 version of key into AES_256_CBC Symetric Key.
    def str_to_key(base64_keystring)
      return( @key = base64_keystring.unpack('m')[0] )
    end

    #Generate random AES_256_CBC initialization vector.
    #  @return [String] Binary initialization vector @iv
    def gen_iv
      return (@iv = OpenSSL::Cipher::Cipher.new(AES_256_CBC).random_iv)
    end   

    #  @return [String] return Base64 version of initialization vector @iv 
    def iv_to_s
      return([@iv].pack('m')).chomp
    end
    
    #  @param [String] turns base64 version of iv into AES_256_CBC initialization vector.
    #  @return [Array] AES_256_CBC initialization vector @iv.
    def str_to_iv(base64_iv_string)
      return (@iv = base64_iv_string.unpack('m')[0])
    end

    #  @return [String] base64 version of @key
    #  @return [String] return Base64 version of initialization vector @iv 
    def key_iv_to_s
      return key_to_s, iv_to_s
    end
      
    #Encrypts source using AES 256 CBC, using @key and @iv
    #  @param unencrypted_source [String|File] 
    #  @return [String] Binary string representing encrypted source
    def encrypt(unencrypted_source)
      unencrypted_source = StringIO.new(unencrypted_source) if(unencrypted_source.class == String)
      aes = OpenSSL::Cipher::Cipher.new(AES_256_CBC)
      aes.encrypt
      aes.key = @key
      aes.iv = @iv
      @cipher_text = ""
      while (s = unencrypted_source.read(4096)) != nil do @cipher_text << aes.update(s); end
      @cipher_text << aes.final
    end
    
    #Converts encrypted source String, @cipher_text, into Base64 String
    #  @param unencrypted_source [String|File] If present, then this source is encrypted, otherwise assumes already encrypted.
    #  @return [String] Base64 string representing encrypted source
    def cipher_to_s(unencrypted_source = nil)
      encrypt(unencrypted_source) if(unencrypted_source != nil)
      return [@cipher_text].pack('m').chomp
    end

    #Decrypts source using AES 256 CBC, using @key and @iv
    #  @param encrypted_source [String|File] 
    #  @param base64_source [Boolean] if true, then source is assumed to be base64 encoded.
    #  @return [String] String representing the original unencypted source
    def decrypt(encrypted_source, base64_source = false)
      encrypted_source = StringIO.new(encrypted_source) if(encrypted_source.class == String)
      read_count = base64_source ? 5464:4096
      decode_cipher = OpenSSL::Cipher::Cipher.new(AES_256_CBC)
      decode_cipher.decrypt
      decode_cipher.key = @key
      decode_cipher.iv = @iv
      @plain_text = ""
      while (et = encrypted_source.read(read_count)) != nil do 
        @plain_text << (base64_source ? decode_cipher.update(et.unpack('m')[0]) : decode_cipher.update(et))
      end
      @plain_text << decode_cipher.final
    end
    
    #Generates a new key using Digest SHA256 in @key.
    #  @return [String] Base64 encoded string, @key
  	def self.gen_key_to_s
  	  aes = self.new
  	  return aes.key_to_s
    end

    #Generate random AES_256_CBC initialization vector.
    #  @return [String] Base64 encoded initialization vector @iv
  	def self.gen_iv_to_s
  	  aes = self.new
  	  return aes.iv_to_s
    end
    
    #Generates a new key using Digest SHA256 in @key, and random AES_256_CBC initialization vector in @iv
    #  @return [String] Base64 encoded string, @key
    #  @return [String] Base64 encoded initialization vector @iv
    def self.gen_key_iv_to_s
  	  aes = self.new
  	  return aes.key_to_s, aes.iv_to_s
    end
      
    #Encrypts source using AES 256 CBC, using @key and @iv
    #  @param unencrypted_source [String|File] 
    #  @param key_string [String] optional base64 key to be used in encryption or decryption. 
    #    if nil, then key and iv are generated automatically. Recover the key with key_to_s(), or key_iv_to_s()
    #  @param iv_string [String ] optional base64 iv (initial vector) to be used in the encryption or decryption
    #    Overwritten by auto generated iv, if key_string is nil. Recover with iv_to_str() or key_iv_to_s().
    #  @return [String] Binary string representing encrypted source
    #  @return [String] base64 key, @key, so later decryption can be done
    #  @return [String] base64 initial vector, @iv, so later decryption can be done
    def self.encrypt(unencrypted_source, key_string = nil, iv_string = nil)
      aes = self.new(key_string, iv_string)
      return aes.encrypt(unencrypted_source), aes.key_to_s, aes.iv_to_s 
    end
    
    #Converts encrypted source String, @cipher_text, into Base64 String
    #  @param unencrypted_source [String|File] which must be present, as AES_256 class is created here.
    #  @param key_string [String] optional base64 key to be used in encryption or decryption. 
    #    if nil, then key and iv are generated automatically. Recover the key with key_to_s(), or key_iv_to_s()
    #  @param iv_string [String ] optional base64 iv (initial vector) to be used in the encryption or decryption
    #    Overwritten by auto generated iv, if key_string is nil. Recover with iv_to_str() or key_iv_to_s().
    #  @return [String] Base64 string representing encrypted source
    #  @return [String] base64 key, @key, so later decryption can be done
    #  @return [String] base64 initial vector, @iv, so later decryption can be done
    def self.cipher_to_s(unencrypted_source, key_string = nil, iv_string = nil)
      aes = self.new(key_string, iv_string)
      return aes.cipher_to_s(unencrypted_source), aes.key_to_s, aes.iv_to_s 
    end
    
    #Creates an AES class and then Decrypts source using AES 256 CBC, using @key and @iv
    #  @param encrypted_source [String|File] 
    #  @param base64_source [Boolean] if true, then source is assumed to be base64 encoded.
    #  @param key_string [String] optional base64 key to be used in encryption or decryption. 
    #    if nil, then key and iv are generated automatically. Recover the key with key_to_s(), or key_iv_to_s()
    #  @param iv_string [String ] optional base64 iv (initial vector) to be used in the encryption or decryption
    #    Overwritten by auto generated iv, if key_string is nil. Recover with iv_to_str() or key_iv_to_s().
    #  @return [String] String representing the original unencypted source
    def self.decrypt(encrypted_source, base64_source=false, key_string = nil, iv_string = nil)
      aes = self.new(key_string, iv_string)
      return aes.decrypt(encrypted_source, base64_source)
    end
  end
end


