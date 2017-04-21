# hash-password-pbkdf2
Simple password hash library with pbkdf2 and sha512 using auto generated salt.

## Install

    $ npm install hash-password-pbkdf2

# Usage

    const pbkdf2 = require("hash-password-pbkdf2")
    
    const hash = pbkdf2.hashSync("PASSWORD")
    // ImlCGpDKiqn7HWlNgEe6RCw==0aLBmmDdvEGZDhHVx5uqxMh9NakpntaYrEfFans8DS4=
    // ^|         salt          ||                   hash                  |
    // iterations base64 encoded
    
    const ok = pbkdf2.validateSync("PASSWORD", hash)
    // true
    
    // Async with Promise
    pbkdf2.hash("PASSWORD")
    pbkdf2.validate("PASSWORD", hash)
    
    // Option
    const hash = pbkdf2.hashSync("PASSWORD", iterations)
    // Iterate 2^n. iteration must be between 0 and 63
    // Default is 15 (32768 iterations).

