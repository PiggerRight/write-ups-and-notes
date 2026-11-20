# Check key

## Challenge

After extracting the given `rev_check-key.tar.gz`, the challenge provides a single executable named `check_key.exe`.

---

## Initial Thoughts

I first checked the file type and ran the program to see how it behaves.

<img width="850" height="209" alt="image" src="https://github.com/user-attachments/assets/9f0f34f8-91c6-4406-be9a-514bb2f2f051" />

Then I loaded the executable into IDA for a closer look.

---

## Solution

Based on the program's behavior, I searched for strings such as `"Try again to be handsome"`. This found:

<img width="481" height="96" alt="image" src="https://github.com/user-attachments/assets/ceb5e6a8-fac6-488f-be6f-eabe3845ab0c" />

I then jumped to that address with `G`.

<img width="513" height="122" alt="image" src="https://github.com/user-attachments/assets/a55ebea5-6b62-4555-a97c-1de93116b2e4" />

I went through the functions that reference this string and picked the one at `DATA XREF: main+7B↑o`.

Next, I decompiled that function with `F5`. After reading through it, I was fairly sure the flag checker is this part:

<img width="622" height="448" alt="image" src="https://github.com/user-attachments/assets/bda0ece4-8177-429f-a290-d92d43e5dcf8" />

Before simplifying the code, I checked what the three unfamiliar names refer to. `vars0` appears to point to the buffer that holds the input,

<img width="251" height="79" alt="image" src="https://github.com/user-attachments/assets/b51d5024-af09-4598-ad4d-8de5eabdaff0" />

`unk_2060` points to a 64-byte array,

<img width="499" height="227" alt="image" src="https://github.com/user-attachments/assets/21df8f24-ba94-4b8e-99c7-64a1d6b85da7" />

and `xmmword_20A0` holds a 16-byte value.

<img width="487" height="45" alt="image" src="https://github.com/user-attachments/assets/10455249-1b60-490a-bc9b-28dde0f9c656" />

Based on this information, I simplified the code below, where `input` is the string read with `cin >> input`. In this pseudocode, `checker[counter]` and `input[counter]` each stand for a 16-byte block starting at that index:

```c
checker = {
    0x0B, 0x02, 0x1A, 0x0C, 0x0A, 0x32, 0x2A, 0x21,
    0x7A, 0x2A, 0x22, 0x16, 0x22, 0x7A, 0x30, 0x16,
    0x2A, 0x3B, 0x7D, 0x2A, 0x22, 0x7A, 0x2D, 0x16,
    0x7F, 0x2F, 0x78, 0x2D, 0x7D, 0x7F, 0x2A, 0x2D,
    0x7F, 0x7C, 0x7C, 0x7E, 0x7D, 0x7A, 0x71, 0x2B,
    0x7C, 0x70, 0x7F, 0x71, 0x7D, 0x2C, 0x7D, 0x2A,
    0x7E, 0x78, 0x7E, 0x2B, 0x2A, 0x71, 0x7D, 0x2D,
    0x79, 0x2D, 0x7D, 0x70, 0x2D, 0x7B, 0x7B, 0x34,
} // 64 bytes

constant = 0x49494949494949494949494949494949 // 16 bytes

// Enter password

if (input.length == 64)
{
    counter = 0;
    v7 = 0;
    do
    {
      v10 = checker[counter] ^ constant ^ input[counter];

      v11 = _mm_unpackhi_epi8(v10, 0);
      v12 = _mm_unpackhi_epi16(v11, 0) | _mm_unpacklo_epi16(v11, 0);
      v13 = _mm_unpacklo_epi8(v10, 0);
      v7 = v7 | (v12 | (_mm_unpackhi_epi16(v13, 0) | _mm_unpacklo_epi16(v13, 0)));

      counter += 16;
    }
    while ( counter != 64 );

    v14 = v7 | _mm_srli_si128(v7, 8);
    v15 = _mm_cvtsi128_si32(v14 | _mm_srli_si128(v14, 4));

    if ( v15 != 0 )
        // Wrong
    else
        // Accepted
}
else
{
    // Wrong
}
```

To understand what the strange operations do, I annotated the loop by tracking the value of each byte through it:

```c
// (checker table: same 64 bytes as above)

constant = 0x49494949494949494949494949494949 // 16 bytes

// Enter password

if (input.length == 64)
{
    counter = 0;
    v7 = 0;
    do
    {
      v10 = checker[counter] ^ constant ^ input[counter];
      // v10 holds 16 bytes --> [b_0, b_1, b_2, ..., b_15]

      v11 = _mm_unpackhi_epi8(v10, 0);
      // --> [b_8,0, b_9,0, b_10,0, b_11,0, b_12,0, b_13,0, b_14,0, b_15,0]

      v12 = _mm_unpackhi_epi16(v11,0) | _mm_unpacklo_epi16(v11,0);
      // --> [b_12|b_8,0,0,0, b_13|b_9,0,0,0, b_14|b_10,0,0,0, b_15|b_11,0,0,0]

      v13 = _mm_unpacklo_epi8(v10,0);
      // --> [b_0,0, b_1,0, b_2,0, b_3,0, b_4,0, b_5,0, b_6,0, b_7,0]

      v7 = v7 | (v12 | (_mm_unpackhi_epi16(v13, 0) | _mm_unpacklo_epi16(v13, 0)));
      // --> [b_12|b_8|b_4|b_0,0,0,0, b_13|b_9|b_5|b_1,0,0,0, b_14|b_10|b_6|b_2,0,0,0, b_15|b_11|b_7|b_3,0,0,0]
      // v7 keeps accumulating (ORing) across all 4 iterations

      counter += 16; // 4 iterations process all 64 bytes
    }
    while ( counter != 64 );

    v14 = v7 | _mm_srli_si128(v7, 8);
    v15 = _mm_cvtsi128_si32(v14 | _mm_srli_si128(v14, 4));
    // v15 is the OR of all 64 difference bytes from the 4 iterations

    if ( v15 != 0 ) // v15 must be 0 for the password to be accepted
        // Wrong
    else
        // Accepted
}
else
{
    // Wrong
}
```

With the OR operation, neither changes whether a byte is zero. Therefore the function checks whether the OR of all the difference bytes (from `v10`) is zero, which means every difference byte must be zero.

Each difference byte is `checker[i] ^ 0x49 ^ input[i]`, so it is zero only if `input[i] == checker[i] ^ 0x49`. In other words, each byte of `input` must equal the matching byte of `checker` XORed with `0x49`. Now we can build a solver for the flag:

```py
checker = [
    0x0B, 0x02, 0x1A, 0x0C, 0x0A, 0x32, 0x2A, 0x21,
    0x7A, 0x2A, 0x22, 0x16, 0x22, 0x7A, 0x30, 0x16,
    0x2A, 0x3B, 0x7D, 0x2A, 0x22, 0x7A, 0x2D, 0x16,
    0x7F, 0x2F, 0x78, 0x2D, 0x7D, 0x7F, 0x2A, 0x2D,
    0x7F, 0x7C, 0x7C, 0x7E, 0x7D, 0x7A, 0x71, 0x2B,
    0x7C, 0x70, 0x7F, 0x71, 0x7D, 0x2C, 0x7D, 0x2A,
    0x7E, 0x78, 0x7E, 0x2B, 0x2A, 0x71, 0x7D, 0x2D,
    0x79, 0x2D, 0x7D, 0x70, 0x2D, 0x7B, 0x7B, 0x34,
]

constant = 0x49

for i in checker:
    print(chr(i ^ constant), end='')
```

Flag:

```text
BKSEC{ch3ck_k3y_cr4ck3d_***************************************}
```

## Key Takeaways

At first, I struggled with the strange SIMD functions such as `_mm_unpackhi_epi8` and `_mm_srli_si128`, but after analyzing them manually, byte by byte, I understood that they only widen and merge the data. The whole loop is just an "OR all the XOR differences and compare with zero" check, which means every byte must match. Compilers can turn a simple loop into dense SIMD code, so it helps to reduce unfamiliar code to a pattern you already know.

## References

- [BKSEC Training](https://training.bksec.vn/)
