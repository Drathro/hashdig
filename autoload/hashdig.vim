" Name: hashdig.vim, Vim global plugin for generating hashed message digests
" Creator: Daniel Wright
" License: MIT license
" Note: sha1 algorithm adapted from FIPS Publication 180-4

"MIT License
"
"Copyright (c) 2017 Daniel Wright
"
"Permission is hereby granted, free of charge, to any person obtaining a copy
"of this software and associated documentation files (the "Software"), to deal
"in the Software without restriction, including without limitation the rights
"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
"copies of the Software, and to permit persons to whom the Software is
"furnished to do so, subject to the following conditions:
"
"The above copyright notice and this permission notice shall be included in all
"copies or substantial portions of the Software.
"
"THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
"SOFTWARE.

if exists("g:loaded_hashdig")
    finish
endif
let g:loaded_hashdig=1

let s:WIDTHMASK32=0xFFFFFFFF
let s:SHA1BITS=32
let s:SHA1BLOCKSIZE=512

function Hashdig#sha1(inputText)
" Purpose: sha1 digest
" Args: input string
" Returns: sha1 digest string
    let l:H=s:sha1InitHash()
    let l:M=s:sha1PreprocessText(a:inputText)
    for i in range(1,len(l:M)*s:SHA1BITS/s:SHA1BLOCKSIZE)
        "step 1 Prepare message schedule
        let [l:M,l:W]=s:sha1UpdateSched(l:M)
        "step 2 set working values
        let a=l:H[0]
        let b=l:H[1]
        let c=l:H[2]
        let d=l:H[3]
        let e=l:H[4]
        "step 3
        for t in range(0,79)
            let l:temp=s:Mask32(s:rotl32(a,5)+
                               \s:sha1FSubT(t,b,c,d)+
                               \e+
                               \s:sha1KSubT(t)+
                               \l:W[t])
            let e=d
            let d=c
            let c=s:rotl32(b,30)
            let b=a
            let a=l:temp
        endfor
        "step 4 Compute new hash
        let l:H[0]=s:Mask32(a+l:H[0])
        let l:H[1]=s:Mask32(b+l:H[1])
        let l:H[2]=s:Mask32(c+l:H[2])
        let l:H[3]=s:Mask32(d+l:H[3])
        let l:H[4]=s:Mask32(e+l:H[4])
    endfor
    return printf("%08x%08x%08x%08x%08x",l:H[0],l:H[1],l:H[2],l:H[3],l:H[4])
endf
        
function s:sha1InitHash()
" Purpose: Returns list of inital hash values
" Returns: list of words
    return [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
endfunction

function s:sha1PreprocessText(text)
" Purpose: Converts text to ascii values and pads to a multiple of sha1 block
"          size
" Args: input string
" Returns: input text as list of words
    let l=strlen(a:text)*8
    let k=s:SHA1BLOCKSIZE - ((l+8) % s:SHA1BLOCKSIZE)
    if k<64
        let k+=s:SHA1BLOCKSIZE
    endif
    let k-=64
    let k=k/8
    let l:byteList=[]
    for i in range(0,len(a:text)-1)
        let l:byteList+=[char2nr(a:text[i])]
    endfor
    let l:byteList+=[0x80]+repeat([0],k)
    let l:wordList=[]
    for i in range(0,len(l:byteList)-1,4)
        let l:word=0
        for j in range(0,2)
            let l:word=or(l:word,l:byteList[i+j])
            let l:word=s:ShiftL(l:word,8)
        endfor
        let l:word=or(l:word,l:byteList[i+3])
        let l:wordList+=[l:word]
    endfor
    let l:upperL=s:ShiftR(l,32)
    let l:lowerL=s:Mask32(l)
    return l:wordList+[l:upperL]+[l:lowerL]
endfunction

function s:sha1UpdateSched(M)
" Purpose: Populates sha1 schedule W for each block of input
"          Processed blocks are removed from word list M
" Args: input word list M
" Returns: list:
"           sha1 schedule W
"           input word list M
    let l:pW=[]
    for item in a:M[0:15]
        call add(l:pW,item)
    endfor
    let l:pM=a:M[16:]
    for l:t in range(16,79)
        call add(l:pW,s:rotl32(xor(l:pW[t-16],
                                  \xor(l:pW[t-14],
                                      \xor(l:pW[t-3],l:pW[t-8])))
                              \,1))
    endfor
    return[l:pM,l:pW]
endfunction

function s:sha1Ch(x,y,z)
" Purpose:  sha1 function "Ch"
    return xor(and(a:x,a:y),and(invert(a:x),a:z))
endfunction

function s:sha1Parity(x,y,z)
" Purpose:  sha1 function "Parity"
    return xor(xor(a:x,a:y),a:z)
endfunction

function s:sha1Maj(x,y,z)
" Purpose:  sha1 function "Maj"
    return xor(xor(and(a:x,a:y),and(a:x,a:z)),and(a:y,a:z))
endfunction

function s:sha1FSubT(t,x,y,z)
" Purpose: sha1 function selector
" Args: iteration int, int, int, int
    if a:t<0
        return 0
    elseif a:t<20
        return s:sha1Ch(a:x,a:y,a:z)
    elseif a:t<40
        return s:sha1Parity(a:x,a:y,a:z)
    elseif a:t<60
        return s:sha1Maj(a:x,a:y,a:z)
    elseif a:t<80
        return s:sha1Parity(a:x,a:y,a:z)
    else
        return 0
    endif
endfunction

function s:sha1KSubT(t)
" Purpose: sha1 constant K selector
" Args: iteration int
    if a:t<0
        return 0
    elseif a:t<20
        return 0x5A827999
    elseif a:t<40
        return 0x6ED9EBA1
    elseif a:t<60
        return 0x8F1BBCDC
    elseif a:t<80
        return 0xCA62C1D6
    else
        return 0
endfunction

function s:rotl32(value,shiftwidth)
" Purpose: rotate 32 bit value left shiftwidth positions
" Args: word, int
" Returns: word
    if (a:shiftwidth<0)
        return a:value
    elseif a:shiftwidth>=s:SHA1BITS
        let l:shiftmod=float2nr(fmod(a:shiftwidth,s:SHA1BITS))
    else
        let l:shiftmod=a:shiftwidth
    endif
    return or(s:ShiftL(a:value,l:shiftmod),
             \s:ShiftR(a:value,s:SHA1BITS-l:shiftmod))
endfunction

function s:Mask32(value)
" Returns: value mod 2^32
    return and(a:value,s:WIDTHMASK32)
endfunction

function s:ShiftR(value,shiftwidth)
" Purpose: shift 32 bit word right shiftwidth positions
" Args: word
" Returns: word
    let l:newval=a:value
    for i in range(1,a:shiftwidth)
        let l:newval=l:newval/2
        if s:WIDTHMASK32<0
            let l:newval=and(l:newval,0x7FFFFFFF)
        endif
    endfor
    return l:newval
endfunction

function s:ShiftL(value,shiftwidth)
" Purpose: shift 32 bit word left shiftwidth positions
" Args: word
" Returns: word
    if a:shiftwidth>=s:SHA1BITS
        return 0
    endif
    let l:newval=a:value
    for i in range(1,a:shiftwidth)
        let l:newval=l:newval*2
    endfor
    let l:newval=s:Mask32(l:newval)
    return l:newval
endfunction

" Unit Tests
""""""""""""
function Hashdig#RunTests()
" Purpose: Run all unit tests
" Returns: true if all tests pass
    let v:errors=[]
    call s:UnitTest_Mask32()
    call s:UnitTest_ShiftL()
    call s:UnitTest_ShiftR()
    call s:UnitTest_sha1Ch()
    call s:UnitTest_sha1Parity()
    call s:UnitTest_sha1Maj()
    call s:UnitTest_sha1FSubT()
    call s:UnitTest_Rotl32()
    call s:UnitTest_sha1KSubT()
    call s:UnitTest_sha1InitHash()
    call s:UnitTest_sha1PreprocessText()
    call s:UnitTest_sha1UpdateSched()
    call s:UnitTest_sha1()
    if empty(v:errors)
        echo "ALL TESTS PASSED"
        return 1
    endif
    for item in v:errors
        echo item
    endfor
    echo "FAILED"
    return 0
endfunction

function s:UnitTest_Mask32()
    call assert_equal(0,s:Mask32(0))
    call assert_equal(1,s:Mask32(1))
    if s:WIDTHMASK32<0
        echo "32 bit integers"
        call assert_equal(-2147483648,s:Mask32(float2nr(pow(2,31))))
        call assert_equal(-2,s:Mask32(s:WIDTHMASK32+s:WIDTHMASK32))
    else
        echo "integer bigger than 32 bits"
        call assert_equal(2147483648,s:Mask32(float2nr(pow(2,31))))
        call assert_equal(0,s:Mask32(float2nr(pow(2,32))))
        call assert_equal(4294967294,s:Mask32(s:WIDTHMASK32+s:WIDTHMASK32))
    endif
endfunction

function s:UnitTest_ShiftR()
    call assert_equal(10,s:ShiftR(21,1))
    call assert_equal(0,s:ShiftR(1,1))
    call assert_equal(0,s:ShiftR(0,1))
    call assert_equal(0,s:ShiftR(21,5))
    call assert_equal(2,s:ShiftR(21,3))
    call assert_equal(32768,s:ShiftR(float2nr(pow(2,32)),17))
endfunction

function s:UnitTest_ShiftL()
    call assert_equal(2,s:ShiftL(1,1))
    call assert_equal(2,s:ShiftL(2,0))
    call assert_equal(0,s:ShiftL(1,32))
    call assert_equal(2147483648,s:ShiftL(1,31))
    call assert_equal(2818572288,s:ShiftL(21,27))
    call assert_equal(2818572288,s:ShiftL(53,27))
endfunction

function s:UnitTest_sha1Ch()
    call assert_equal(0,s:sha1Ch(0,0,0))
    call assert_equal(1,s:sha1Ch(0,0,1))
    call assert_equal(0,s:sha1Ch(0,1,0))
    call assert_equal(1,s:sha1Ch(0,1,1))
    call assert_equal(0,s:sha1Ch(1,0,0))
    call assert_equal(0,s:sha1Ch(1,0,1))
    call assert_equal(1,s:sha1Ch(1,1,0))
    call assert_equal(1,s:sha1Ch(1,1,1))
    call assert_equal(745685733,s:sha1Ch(53436,346532,745673453))
endfunction

function s:UnitTest_sha1Parity()
    call assert_equal(0,s:sha1Parity(0,0,0))
    call assert_equal(1,s:sha1Parity(0,0,1))
    call assert_equal(1,s:sha1Parity(0,1,0))
    call assert_equal(0,s:sha1Parity(0,1,1))
    call assert_equal(1,s:sha1Parity(1,0,0))
    call assert_equal(0,s:sha1Parity(1,0,1))
    call assert_equal(0,s:sha1Parity(1,1,0))
    call assert_equal(1,s:sha1Parity(1,1,1))
    call assert_equal(746032117,s:sha1Parity(53436,346532,745673453))
endfunction

function s:UnitTest_sha1Maj()
    call assert_equal(0,s:sha1Maj(0,0,0))
    call assert_equal(0,s:sha1Maj(0,0,1))
    call assert_equal(0,s:sha1Maj(0,1,0))
    call assert_equal(1,s:sha1Maj(0,1,1))
    call assert_equal(0,s:sha1Maj(1,0,0))
    call assert_equal(1,s:sha1Maj(1,0,1))
    call assert_equal(1,s:sha1Maj(1,1,0))
    call assert_equal(1,s:sha1Maj(1,1,1))
    call assert_equal(20652,s:sha1Maj(53436,346532,745673453))
endfunction

function s:UnitTest_sha1FSubT()
    call assert_equal(745685733,s:sha1FSubT(0,53436,346532,745673453))
    call assert_equal(745685733,s:sha1FSubT(19,53436,346532,745673453))
    call assert_equal(746032117,s:sha1FSubT(20,53436,346532,745673453))
    call assert_equal(746032117,s:sha1FSubT(39,53436,346532,745673453))
    call assert_equal(20652,s:sha1FSubT(40,53436,346532,745673453))
    call assert_equal(20652,s:sha1FSubT(59,53436,346532,745673453))
    call assert_equal(746032117,s:sha1FSubT(60,53436,346532,745673453))
    call assert_equal(746032117,s:sha1FSubT(79,53436,346532,745673453))
    call assert_equal(0,s:sha1FSubT(80,53436,346532,745673453))
endfunction

function s:UnitTest_Rotl32()
    call assert_equal(2,s:rotl32(1,1))
    call assert_equal(1,s:rotl32(1,0))
    call assert_equal(1,s:rotl32(1,32))
    call assert_equal(2,s:rotl32(1,33))
    if s:WIDTHMASK32<0
        echo "32 bit integers"
        call assert_equal(-2147483648,s:rotl32(1,31))
        call assert_equal(-2147483648,s:rotl32(-2147483648,0))
        call assert_equal(1,s:rotl32(-2147483648,1))
    else
        echo "integer bigger than 32 bits"
        call assert_equal(2147483648,s:rotl32(1,31))
        call assert_equal(2147483648,s:rotl32(2147483648,0))
        call assert_equal(1,s:rotl32(2147483648,1))
    endif
endfunction

function s:UnitTest_sha1KSubT()
    if s:WIDTHMASK32>0
        call assert_equal(1518500249,s:sha1KSubT(0))
        call assert_equal(1518500249,s:sha1KSubT(19))
        call assert_equal(1859775393,s:sha1KSubT(20))
        call assert_equal(1859775393,s:sha1KSubT(39))
        call assert_equal(2400959708,s:sha1KSubT(40))
        call assert_equal(2400959708,s:sha1KSubT(59))
        call assert_equal(3395469782,s:sha1KSubT(60))
        call assert_equal(3395469782,s:sha1KSubT(79))
    endif
endfunction

function s:UnitTest_sha1InitHash()
    if s:WIDTHMASK32>0
        let H=s:sha1InitHash()
        call assert_equal(1732584193,H[0])
        call assert_equal(4023233417,H[1])
        call assert_equal(2562383102,H[2])
        call assert_equal(271733878,H[3])
        call assert_equal(3285377520,H[4])
    endif
endfunction

function s:UnitTest_sha1PreprocessText()
    call assert_equal([1633837952]+repeat([0],14)+[24],
                     \s:sha1PreprocessText("abc"))
    let l:utIn="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let l:utOut=[0x61626364,0x62636465,0x63646566,0x64656667,
                 \0x65666768,0x66676869,0x6768696A,0x68696A6B,
                 \0x696A6B6C,0x6A6B6C6D,0x6B6C6D6E,0x6C6D6E6F,
                 \0x6D6E6F70,0x6E6F7071,0x80000000]+repeat([0],16)+[0x000001C0]
    call assert_equal(l:utOut,s:sha1PreprocessText(l:utIn))
    call assert_equal(0,len(utOut) % 16)
endfunction

function s:UnitTest_sha1UpdateSched()
    let l:utM=[0x61626364,0x62636465,0x63646566,0x64656667,
              \0x65666768,0x66676869,0x6768696A,0x68696A6B,
              \0x696A6B6C,0x6A6B6C6D,0x6B6C6D6E,0x6C6D6E6F,
              \0x6D6E6F70,0x6E6F7071,0x80000000]+repeat([0],16)+[0x000001C0]
    let l:utMOrig=deepcopy(l:utM)
    let [l:utM,l:utW]=s:sha1UpdateSched(l:utM)
    call assert_equal(l:utMOrig[0:15],l:utW[0:15])
    call assert_equal(80,len(l:utW))
    call assert_equal(len(l:utMOrig)-16,len(l:utM))
    call assert_equal(168180286,l:utW[16])
    let [l:utM,l:utW]=s:sha1UpdateSched(l:utM)
    call assert_equal(l:utMOrig[16:],l:utW[0:15])
    call assert_equal(80,len(l:utW))
    call assert_equal(len(l:utMOrig)-32,len(l:utM))
    call assert_equal(0,l:utW[16])
endfunction

function s:UnitTest_sha1()
    call assert_equal("b7e23ec29af22b0b4e41da31e868d57226121c84",
                     \Hashdig#sha1("hello, world"))
    call assert_equal("a9993e364706816aba3e25717850c26c9cd0d89d",
                     \Hashdig#sha1("abc"))
    let l:utIn="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    call assert_equal("84983e441c3bd26ebaae4aa1f95129e5e54670f1",
                     \Hashdig#sha1(l:utIn))
endfunction

