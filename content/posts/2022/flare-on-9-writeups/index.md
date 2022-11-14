---
title: "Flare-On 9 Writeups"
date: 2022-11-14T13:15:00+01:00
draft: false
toc: true
images:
tags: 
  - reverse
  - ctf
---

Here are (some ?) writeups for this year Flare-On challenge.
I'll add more in the coming days.

For reference here is my timing:

![timing](00-timing.jpeg)

# 0. TOC


1. [Flaredle](#1-flaredle)

2. [PixelPoker](#2-pixelpoker)

3. [Magic 8 Ball](#3-magic-8-ball)

4. [darn_mice](#4-darn_mice)

5. [T8](#5-t8)

6. [a la mode](#6-a-la-mode)

7. [anode](#7-anode)

8. [backdoor](#8-backdoor)

9. [encryptor](#9-encryptor)

10. [Nur getraumt](#10-nur-getraumt)

11. [The challenge that shall not be named](#11-the-challenge-that-shall-not-be-named)





# 1. Flaredle

Small javascript webapp where we need to guess a word.

Open ```script.js```, starts with:

```javascript
import { WORDS } from "./words.js";

const NUMBER_OF_GUESSES = 6;
const WORD_LENGTH = 21;
const CORRECT_GUESS = 57;
let guessesRemaining = NUMBER_OF_GUESSES;
let currentGuess = [];
let nextLetter = 0;
let rightGuessString = WORDS[CORRECT_GUESS];
```

find correct flag condition:

```javascript
    if (guessString === rightGuessString) {
        let flag = rightGuessString + '@flare-on.com';
        toastr.options.timeOut = 0;
        toastr.options.onclick = function() {alert(flag);} 
        toastr.success('You guessed right! The flag is ' + flag);
        
        guessesRemaining = 0
        return
    } 
```

we know that ```rightGuessString = WORDS[CORRECT_GUESS]``` and that ```CORRECT_GUESS = 57```, so we can just pick it up in the array from ```words.js```

```bash
% cat -n words.js | grep " $((57+1))"       # because array starts at 0
    58		'flareonisallaboutcats',
```


flag: ```flareonisallaboutcats@flare-on.com```



# 2. PixelPoker

(who knows when ?)


# 3. Magic 8 Ball

(coming soon ?)


# 4. darn_mice

(probably anytime soon ?)


# 5. T8

(maybe some day ?)


# 6. a la mode

(coming soon ?)



# 7. anode

We're getting a big fat 55MB binary.
After poking it a bit with a stick, it turns out it's a javascript script, packed with [nexe](https://github.com/nexe/nexe).

if we run ```strings``` on it we can actually see the script at the end along with the ```<nexe~~sentinel>``` marker.

Unpacking (such big word...) the script using some random nexe unpacker or even with ```strings```, we're left with something like that:

```javascript
readline.question(`Enter flag: `, flag => { 
  readline.close();
  if (flag.length !== 44) {
    console.log("Try again.");
    process.exit(0);
  }
  var b = [];
  for (var i = 0; i < flag.length; i++) {
    b.push(flag.charCodeAt(i));
  }

  // something strange is happening...
  if (1n) {
    console.log("uh-oh, math is too correct...");
    process.exit(0);
  }

  var state = 1337;
  while (true) {
    state ^= Math.floor(Math.random() * (2**30));
    switch (state) {
      case 306211:
        if (Math.random() < 0.5) {
          b[30] -= b[34] + b[23] + b[5] + b[37] + b[33] + b[12] + Math.floor(Math.random() * 256);
          b[30] &= 0xFF;
        } else {
          b[26] -= b[24] + b[41] + b[13] + b[43] + b[6] + b[30] + 225; 
          b[26] &= 0xFF;
        }
        state = 868071080;
        continue;
      case 311489:
        if (Math.random() < 0.5) {
          b[10] -= b[32] + b[1] + b[20] + b[30] + b[23] + b[9] + 115;
          b[10] &= 0xFF;
        } else {
          b[7] ^= (b[18] + b[14] + b[11] + b[25] + b[31] + b[21] + 19) & 0xFF;
        }
        state = 22167546;
        continue;

// snipp... there's 1025 case statement

      default:
        console.log("uh-oh, math.random() is too random...");
        process.exit(0); 
    }   
    break;
  }     
      
  var target = [106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74, 139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153, 223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76];     
  if (b.every((x,i) => x === target[i])) {
    console.log('Congrats!');
  } else {
    console.log('Try again.');
  }     
});
```

We're just asked to enter a string of 44 characters, which is then processed by the state machine and finally compared byte by byte with the target array.

When i saw that state machine loop i initially thought it would be some sort of control flow flattening to break, but noticed none of the next state calculation actually depends on any condition, so
easy game: run with nodejs, dump state to get correct order and profit (or something like that).

However:

```
% node anode.js
Enter flag: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
uh-oh, math is too correct...
```


2 things here are complicating my initial statement:
- the state machine is not going to work properly when the state is "random":
```javascript
state ^= Math.floor(Math.random() * (2**30));
```
- there's some funky things happening with BigInt (comment is not lying):
```javascript
  // something strange is happening...
  if (1n) {
    console.log("uh-oh, math is too correct...");
    process.exit(0);
  }
```

soooo... that nexe bundle must be packed with a modified node.exe, like with a not so random random().


Looking at it in ghidra, finding ```v8::base::RandomNumberGenerator::SetSeed```


```C
void thiscall v8::base::RandomNumberGenerator::SetSeed(RandomNumberGenerator *this,int64 param_1)

{
                    /* 0xd8dc60  11842  ?SetSeed@RandomNumberGenerator@base@v8@@QEAAX_J@Z */
    (__int64)this = param_1;
    (undefined8)(this + 8) = 0x60c43c4809ad2d74;
    (undefined8)(this + 0x10) = 0xce6a1a53db4c5403;
    return;
}
```

We can see that it has indeed be patched to set the PRNG initial state to a fixed value, instead of anyting supplied to the SetSeed function.

As compared to the original: [https://chromium.googlesource.com/v8/v8/+/6d706ae3a0153cf0272760132b775ae06ef13b1a/src/base/utils/random-number-generator.cc#207](https://chromium.googlesource.com/v8/v8/+/6d706ae3a0153cf0272760132b775ae06ef13b1a/src/base/utils/random-number-generator.cc#207)


Lot of crazy ideas going into my head at this time, like reimplementing the PRNG and/or dumping all its (firsts) values, etc... 

But all of these would also require me to dig more into the patched node.exe to find out what has been done to BigInt as well, nothing i wanted to do at the moment...

Since the script's logic is only valid when ran with the patched node.exe, if i wanted to debug the js, i needed a way to have a modified script executed by this binary.

Turned out, you can edit the script straight inside the binary and you dont have to change anything else as long as its size doesn't change.

Handy and time for cringe...


In the extracted script, let's change this:
```javascript
  // something strange is happening...
  if (1n) {
    console.log("uh-oh, math is too correct...");
    process.exit(0);
  }
```

by

```javascript
  // happening.....
  l = console.log;
  if (1n) {
    console.log("uh-oh, math is too correct...");
    process.exit(0);
  }

```

so we can use ```l``` instead of ```console.log```: that should fit fine in all the useless whitespaces (aka indentations).

Then use a stupid script make the JS print all operation:

```python
import re

def fix_line(line):
    ori_len = len(line)
    expr = re.findall("^ +(.*?);$", line)[0]
    new_line = 'l("%s");'%expr

    new_line = new_line.replace('Math.floor(Math.random() * 256)',
                                '"+Math.floor(Math.random() * 256)+"')

    n_space = ori_len - len(new_line) - 1
    new_line = ' '*n_space + new_line
    return new_line

with open("patched_anode.tmpl", "r") as fp:
    for line in fp:
        if re.match("^ +b\[", line):
            print(fix_line(line))
        else:
            pass
            print(line, end='')
```

the result looks like:
```javascript
  while (true) {
    state ^= Math.floor(Math.random() * (2**30));
    switch (state) {
      case 306211:
        if (Math.random() < 0.5) {
 l("b[30] -= b[34] + b[23] + b[5] + b[37] + b[33] + b[12] + "+Math.floor(Math.random() * 256)+"");
     l("b[30] &= 0xFF");
        } else {
     l("b[26] -= b[24] + b[41] + b[13] + b[43] + b[6] + b[30] + 225");
     l("b[26] &= 0xFF");
        }
        state = 868071080;
        continue;
      case 311489:
        if (Math.random() < 0.5) {
     l("b[10] -= b[32] + b[1] + b[20] + b[30] + b[23] + b[9] + 115");
     l("b[10] &= 0xFF");
        } else {
     l("b[7] ^= (b[18] + b[14] + b[11] + b[25] + b[31] + b[21] + 19) & 0xFF");
        }
        state = 22167546;
        continue;
```

and should have the same size than the original script:
```
% ls -l inj.js patched_anode.tmpl
316 -rw-r--r-- 1 matth matth 321847 Oct  3 09:19 inj.js
316 -rw-r--r-- 1 matth matth 321847 Oct  3 09:09 patched_anode.tmpl
```

we can then push it back into the binary using advanced parasite code injection (sic):

```python
import sys

with open("anode.exe", "rb") as fp:
    header = fp.read(0x35e3806)
    fp.seek(0x363213d)
    footer = fp.read()

patch = open(sys.argv[1], "rb").read()

with open("ppp_anode.exe", "wb") as fp:
    fp.write(header)
    fp.write(patch)
    fp.write(footer)
```


we then a new binary ```ppp_anode.exe```, which when executed produces a trace like:

```
% head -20 conds.txt
b[29] -= b[37] + b[23] + b[22] + b[24] + b[26] + b[10] + 7
b[29] &= 0xFF
b[39] += b[34] + b[2] + b[1] + b[43] + b[20] + b[9] + 79
b[39] &= 0xFF
b[19] ^= (b[26] + b[0] + b[40] + b[37] + b[23] + b[32] + 255) & 0xFF
b[28] ^= (b[1] + b[23] + b[37] + b[31] + b[43] + b[42] + 245) & 0xFF
b[39] += b[42] + b[10] + b[3] + b[41] + b[14] + b[26] + 177
b[39] &= 0xFF
b[9] -= b[20] + b[19] + b[22] + b[5] + b[32] + b[35] + 151
b[9] &= 0xFF
b[14] -= b[4] + b[5] + b[31] + b[15] + b[36] + b[40] + 67
b[14] &= 0xFF
b[33] += b[25] + b[12] + b[14] + b[34] + b[4] + b[36] + 185
b[33] &= 0xFF
b[12] -= b[21] + b[23] + b[0] + b[32] + b[28] + b[17] + 252
b[12] &= 0xFF
b[43] += b[10] + b[15] + b[28] + b[29] + b[27] + b[26] + 168
b[43] &= 0xFF
b[18] ^= (b[32] + b[30] + b[26] + b[22] + b[9] + b[33] + 19) & 0xFF
b[8] += b[18] + b[41] + b[1] + b[3] + b[16] + b[43] + 139
```

so we know what have to solve, the issue is there's a lot of operations:

```
% wc -l conds.txt
1704 conds.txt
```

Despites hearing several people claiming z3 wont work on this, i convinced myself i was smarter (spoiler alert, i'm not) and squeezed everything into z3 and went for lunch or something.

It kept running and running until i got bored and convinced myself to change the approach and try something which was too dumb to be true: just execute from the bottom up, switching + and - operations...

warning: what follows can hurt the eyes :)

- reverse all lines and switch additions and substractions:
```
%  cat conds.txt | tac | sed -e 's/+=/@=/' -e 's/-=/+=/' -e 's/@=/-=/' > rev.txt
```

- execute with a small wrapper:
```python
from claripy import BVV

# from js
target = [106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74, 139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153, 223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76]

# keep it on 8 bits the lazy way...
b = [BVV(_, 8) for _ in target]

# more advanced stuff... :)
exec(open("rev.txt").read())

# result of heavy calculations
print(b)
```

- get byte values (too lazy to find out how to convert claripy BVV to actual int):
```bash
% python exe.py | sed -e 's/<BV8//g' -e 's/>//g'
[ 110,  48,  116,  95,  106,  117,  53,  116,  95,  65,  95,  106,  52,  118,  97,  83,  67,  114,  105,  80,  55,  95,  99,  104,  52,  108,  49,  101,  110,  103,  51,  64,  102,  108,  97,  114,  101,  45,  111,  110,  46,  99,  111,  109]
```

- profit:

```
% python
Python 3.10.8 (main, Nov  4 2022, 09:21:25) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> lolz = [ 110,  48,  116,  95,  106,  117,  53,  116,  95,  65,  95,  106,  52,  118,  97,  83,  67,  114,  105,  80,  55,  95,  99,  104,  52,  108,  49,  101,  110,  103,  51,  64,  102,  108,  97,  114,  101,  45,  111,  110,  46,  99,  111,  109]
>>> ''.join([chr(_) for _ in lolz])
'n0t_ju5t_A_j4vaSCriP7_ch4l1eng3@flare-on.com'
```




# 8. backdoor

(might open soon ?)


# 9. encryptor

(am i losing my time ?)


# 10. Nur getraumt

(99 luftballon)


# 11. The challenge that shall not be named

(do i need a shrubbery ?)

