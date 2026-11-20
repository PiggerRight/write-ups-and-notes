# babylua

## Challenge

After extracting the given `rev_babylua.tar.gz`, the challenge provides two files, `main.lua` and `flag.lua`.

---

## Initial Thoughts

I first checked the file types.

<img width="595" height="134" alt="image" src="https://github.com/user-attachments/assets/8887420b-2f1b-4a4d-b445-8134efd983a8" />

`main.lua` is an ASCII text file, so I read it directly.

<img width="547" height="145" alt="image" src="https://github.com/user-attachments/assets/044f1cad-48ee-40d2-adb3-6bc1594f7249" />

This code reads a line from the keyboard and passes it to a check function, together with the string `'ThisIsAFlag'`, to decide whether the input is the flag. The check function must be defined in `flag.lua`.

However, `flag.lua` is a compiled Lua 5.3 bytecode file, so I used a Lua decompiler to examine it.

---

## Solution

After decompiling, the code of `flag.lua` is:

Note: at the start, the function builds a 28-element array. I shortened that part with `...`.

```lua
local L0_1, L1_1
L0_1 = {}

function L1_1(A0_2, A1_2)
  local L2_2, L3_2, L4_2, L5_2, L6_2, L7_2, L8_2, L9_2, L10_2, L11_2, L12_2, L13_2, L14_2, L15_2, L16_2, L17_2, L18_2, L19_2, L20_2, L21_2, L22_2, L23_2, L24_2, L25_2, L26_2, L27_2, L28_2, L29_2, L30_2

  L2_2 = {}
  L3_2 = 22
  L4_2 = 101
  ...
  L30_2 = 114

  L2_2[1] = L3_2
  L2_2[2] = L4_2
  ...
  L2_2[28] = L30_2

  L3_2 = #A0_2
  L4_2 = #L2_2
  if L3_2 ~= L4_2 then
    L3_2 = false
    return L3_2
  end
  L3_2 = 1
  L4_2 = #L2_2
  L5_2 = 1
  for L6_2 = L3_2, L4_2, L5_2 do
    L8_2 = A0_2
    L7_2 = A0_2.byte
    L9_2 = L6_2
    L7_2 = L7_2(L8_2, L9_2)
    L9_2 = A1_2
    L8_2 = A1_2.byte
    L10_2 = L6_2 - 1
    L11_2 = #A1_2
    L10_2 = L10_2 % L11_2
    L10_2 = L10_2 + 1
    L8_2 = L8_2(L9_2, L10_2)
    L7_2 = L7_2 ~ L8_2
    if 1 < L6_2 then
      L9_2 = A0_2
      L8_2 = A0_2.byte
      L10_2 = L6_2 - 1
      L8_2 = L8_2(L9_2, L10_2)
      L7_2 = L7_2 + L8_2
    end
    L8_2 = L2_2[L6_2]
    if L7_2 ~= L8_2 then
      L8_2 = false
      return L8_2
    end
  end
  L3_2 = true
  return L3_2
end

L0_1.check = L1_1
return L0_1
```

Then I simplified the Lua code:

```lua
function check_flag(inputString, checkString)

  checkArray = {
    22, 101, 133, 137, 79, 75, 168, 159, 205, 114, 118, 147, 125, 200, 
    74, 122, 165, 85, 131, 195, 133, 146, 152, 145, 145, 123, 98, 114
  }

  if #inputString ~= #checkArray then -- the input must be as long as checkArray (28)
    return false
  end
 
  for index = 1, #checkArray, 1 do -- in Lua, indexes start at 1, not 0

    L7_2 = string.byte(inputString, index) -- the byte of inputString at position index
    L8_2 = string.byte(checkString, ((index - 1) % #checkString) + 1) -- the byte of checkString, repeated cyclically
    L7_2 = L7_2 ~ L8_2 -- this is XOR operation

    if 1 < index then
      L7_2 += string.byte(inputString, index - 1) -- add the previous byte of inputString
    end

    if L7_2 ~= checkArray[index] then -- if L7_2 != checkArray[index] --> Wrong
      return false
    end

  end
  return true
end
```

As we can see, the function iterates through the input one character at a time and checks that

```py
(inputString[i] ^ checkString[i % len(checkString)]) + inputString[i-1] == checkArray[i]
```

where `i` starts at `0` (so `key[i % len(key)]` repeats the key cyclically), `^` is XOR, and `input[i-1]` is added only when `i > 0`.

Note that in `main.lua`, the `check` function receives two arguments:

- `flag`: the input from the keyboard (`inputString`)
- `'ThisIsAFlag'`: the value for `checkString`, which is the 11-byte key

Each character depends only on the previous one, so we can solve from left to right:

- `inputString[0] = checkArray[0] ^ checkString[0]`
- `inputString[i] = (checkArray[i] - inputString[i-1]) ^ checkString[i % len(checkString)]`

Now we can build a solver for the flag:

```py
checkArray = [
    22, 101, 133, 137, 79, 75, 168, 159, 205, 114, 118, 147, 125, 200, 
    74, 122, 165, 85, 131, 195, 133, 146, 152, 145, 145, 123, 98, 114
]

checkString = 'ThisIsAFlag'

res = [0] * len(checkArray)

for i in range(0,len(checkArray)):
    if i == 0:
        res[i] = checkArray[i] ^ ord(checkString[i%len(checkString)])
    else:
        res[i] = (checkArray[i] - res[i-1]) ^ ord(checkString[i%len(checkString)])
    print(chr(res[i]),end="")
```

Flag:

```text
BKSEC{lu4_pwn3d_***********}
```

## References

- [BKSEC Training](https://training.bksec.vn/)
- [Lua Decompiler](https://www.decompiler.com/lua)
