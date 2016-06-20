# wikk_aes

* http://wikarekare.github.com/wikk_aes/
* Source https://github.com/wikarekare/wikk_aes
* Gem https://rubygems.org/gems/wikk_aes

## DESCRIPTION:

Class for AES 256 encryption of text. 

## FEATURES/PROBLEMS:

* encrypt takes strings or File (IO) objects
* calls available to base64 encode/pack encrypted output and unencode/unpack before decryption
* calls to base64 encode key and initial vector, and WIKK::AES256 accepts key_string and iv_string arguments.

## SYNOPSIS:

```
require "wikk_aes_256"
  aes2 = WIKK::AES_256.new
  File.open("testfile.txt",'r') do |fd|
    @et = aes2.cipher_to_s(fd)
  end
  puts aes2.decrypt(@et, true)
```

## REQUIREMENTS:


## INSTALL:

* sudo gem install wikk_aes_256

## LICENSE:

(The MIT License)

Copyright (c) 2016

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
