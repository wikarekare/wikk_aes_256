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

puts "*********** test_key_and_iv_generation => calls to gen_key and gen_iv also work *********************"
test_key_and_iv_generation
#puts "*********** test_instance_lvl_encryption *********************"
#test_instance_lvl_encryption
puts "*********** test_class_lvl_encryption/decyption => instance level calls work too *********************"
test_class_lvl_encryption
