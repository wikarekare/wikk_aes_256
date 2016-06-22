require "test/unit"
require "wikk_aes_256"

#Manual test and check.

def test_key_and_iv_generation
  puts WIKK::AES_256.gen_key_iv_to_s
end

def test_instance_lvl_encryption
  aes2 = WIKK::AES_256.new
  File.open("testfile.txt",'r') do |fd|
    @et = aes2.cipher_to_s(fd)
  end
  puts aes2.decrypt(@et, true)
end

def test_class_lvl_encryption
  File.open("testfile.txt",'r') do |fd|
    @et2, @key, @iv = WIKK::AES_256.cipher_to_s(fd)
  end
  puts WIKK::AES_256.decrypt(@et2, true, @key, @iv)
end

def test_nil_key_argument
  aes2 = WIKK::AES_256.new(nil, "cxpzz9BMCOvyqfyngashHA==")
  @et = aes2.cipher_to_s("this is a test string")
  puts aes2.decrypt(@et, true)
end

def test_nil_iv_argument
  aes2 = WIKK::AES_256.new("kzyE95G6OTkvteywPkhvP0Y9RhM8tZxQMnCOTH7LXrA=", nil)
  @et = aes2.cipher_to_s("this is another test string")
  puts aes2.decrypt(@et, true)
end

def test_nil_arguments
  aes2 = WIKK::AES_256.new(nil, nil)
  @et = aes2.cipher_to_s("this is another test string")
  puts aes2.decrypt(@et, true)
end



puts "*********** test_key_and_iv_generation => calls to gen_key and gen_iv also work *********************"
test_key_and_iv_generation
#puts "*********** test_instance_lvl_encryption *********************"
#test_instance_lvl_encryption
puts "*********** test_class_lvl_encryption/decyption => instance level calls work too *********************"
test_class_lvl_encryption

puts "*********** nil key, with string *********************"
test_nil_key_argument
puts "*********** nil iv, with string *********************"
test_nil_iv_argument
puts "*********** nil with string *********************"
test_nil_arguments