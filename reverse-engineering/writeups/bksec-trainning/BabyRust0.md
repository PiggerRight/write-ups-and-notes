# BabyRust0

## Challenge

After extracting the given `rev_babyrust0.tar.gz`, the challenge provides a single executable named `rust0`.

---

## Initial Thoughts

I first checked the file type and ran the program to see how it behaves.

<img width="851" height="287" alt="image" src="https://github.com/user-attachments/assets/4d4cb35b-1c08-418b-9aca-eb83f784d7cd" />


Then I loaded the executable into IDA for a closer look.

---

## Solution

Based on the program's behavior, I searched for strings such as `"Wrong! Please try again"` by using `Alt` + `B` in IDA. This found:

<img width="498" height="113" alt="image" src="https://github.com/user-attachments/assets/dc135b4e-63a4-42de-869c-47d5449c75c1" />

I then jumped to that address with `G`.

<img width="743" height="152" alt="image" src="https://github.com/user-attachments/assets/678de476-7eed-4575-8a8b-8f5a9f95f372" />

I went through the functions that reference this string and picked the one at `DATA XREF: sub_8E60+11↑o`.

Next, I decompiled that function with `F5`. After reading through it, I was fairly sure the flag checker is this part:

<img width="610" height="493" alt="image" src="https://github.com/user-attachments/assets/af628279-f9ea-458a-95c1-93407cba318f" />

I simplified the code below, where `input` is the line the user typed (trimmed of surrounding whitespace by the program):

```c
if ( input.length == 64)
{
    // v33 = xmmword_4A030;
    // v32 = xmmword_4A020;
    // v31 = (__m256i)ymmword_4A000;
    v21 = 17;
    do
    {
    if ( v21 == 81 )
    {
        // Accepted!
    }
    if ( (input[v21 - 17] ^ 0xB3) != *((_BYTE *)&v28 + v21 + 7) ){
        break;
    }
    v23 = (input[v21 - 16] ^ 0xB3) == *((_BYTE *)&v29 + v21);
    v21 += 2;
    }
    while ( v23 );
}
// Wrong!
```

In each iteration, two input bytes, `input[v21 - 17]` and `input[v21 - 16]`, are XORed with `0xB3` and compared with `*((_BYTE *)&v28 + v21 + 7)` and `*((_BYTE *)&v29 + v21)` respectively. `v21` runs from `17` to `81` in steps of `2`, which gives `32` iterations and `64` bytes in total, matching the length check.

At first, `v28` and `v29` looked like data I had to trace, but they never hold anything useful. The interesting variables are `v31`, `v32` and `v33`, which are assigned right before the loop:

<img width="634" height="112" alt="image" src="https://github.com/user-attachments/assets/d7c373fb-243a-4f22-a8e0-abafc914a471" />

Checking the stack layout gives:

```text
v31              → rsp + 40h    (32 bytes of data)
v32              → rsp + 60h    (16 bytes of data)
v33              → rsp + 70h    (16 bytes of data)

v28              → rsp + 28h
v29              → rsp + 30h

With v21 = 17
&v28 + v21 + 7   → rsp + 40h     → v31 + 0h
&v29 + v21       → rsp + 41h     → v31 + 1h
```

So the loop reads a single 64-byte table that starts at `rsp + 40h` and is made of `v31`, `v32` and `v33` in address order. Each input byte, XORed with `0xB3`, must equal the matching table byte. IDA does not recognize that these three variables form one contiguous array, so it shows the accesses as unrelated variables.

The table is a copy of 64 contiguous bytes in `.rodata`, from `0x4A000` to `0x4A03F`. The compiler copies it onto the stack with one 32-byte and two 16-byte values.

To decode the table, we read the three chunks in address order (`v31`, then `v32`, then `v33`):

```text
v31    →     F1F8E0F6F0C8C1C686C7ECC980C183ECC3C4DD80D7ECD6D784D28AD683D78685 (rsp + 40h → rsp + 5Fh)
v32    →     0D78087D18B8481D286D085D6D1D281D2h                               (rsp + 60h → rsp + 6Fh)
v33    →     0CED181D2D580D0838B8284D0808BD580h                               (rsp + 70h → rsp + 7Fh)
```

IDA displays the 16-byte xmmword values (`v32` and `v33`) as single 128-bit little-endian numbers, so their bytes appear reversed (the leading 0 and trailing h are only IDA's hex notation). The 32-byte ymmword (`v31`) has no integer format in IDA, so it is displayed in memory order. We therefore need to reverse the bytes of `v32` and `v33`, but not of `v31`:

```text
v31    →     F1 F8 E0 F6 F0 C8 C1 C6 86 C7 EC C9 80 C1 83 EC C3 C4 DD 80 D7 EC D6 D7 84 D2 8A D6 83 D7 86 85   (rsp + 40h → rsp + 5Fh)
v32    →     D2 81 D2 D1 D6 85 D0 86 D2 81 84 8B D1 87 80 D7                                                   (rsp + 60h → rsp + 6Fh)
v33    →     80 D5 8B 80 D0 84 82 8B 83 D0 80 D5 D2 81 D1 CE                                                   (rsp + 70h → rsp + 7Fh)
```

Finally, XOR each byte with 0xB3 and convert it to ASCII.

Flag:

```text
BKSEC{ru5t_z3r0_pwn3d_*****************************************}
```

## Key Takeaways

At first I struggled with `v28` and `v29`, trying to find what they point to, and I ignored `v31`, `v32` and `v33` because they never appear in the checker loop. In fact, the loop reads them indirectly through offsets from `v28` and `v29`. When simplifying decompiled code, remember that the decompiler may split one buffer into several variables, so compare stack offsets to see what a pointer expression really reads.

## References

- [BKSEC Training](https://training.bksec.vn/)
