# BabyRust0

## Challenge

After un-zip the given `rev_babyrust0.tar.gz`, the challenge provides an executable file named `rust0`.

---

## Initial Thoughts

At first I check the file type and try to run it. 

<img width="851" height="287" alt="image" src="https://github.com/user-attachments/assets/4d4cb35b-1c08-418b-9aca-eb83f784d7cd" />


Then I throw the executable file into IDA for more examination.

---

## Solution

Rely on the behavior of the program, I search for the strings like `"Wrong! Please try again"` by using `alt` + `B` in IDA. Then I found:

<img width="498" height="113" alt="image" src="https://github.com/user-attachments/assets/dc135b4e-63a4-42de-869c-47d5449c75c1" />

Then I move to the IDA view of this position using `fn` + `G` to search for the address.

<img width="743" height="152" alt="image" src="https://github.com/user-attachments/assets/678de476-7eed-4575-8a8b-8f5a9f95f372" />

I look through all functions that have the reference to this string and I decide to continue with `DATA XREF: sub_8E60+11↑o`.

Next, I decompile that function by `f5`. After looking through the function, I quite sure that the flag checker is:

<img width="610" height="493" alt="image" src="https://github.com/user-attachments/assets/af628279-f9ea-458a-95c1-93407cba318f" />


I tried to simplize this code, with `input` is simply the input string:

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

As we can see, in each iteration each two bytes/chars of the input string is `input[v21 - 17]` and `input[v21 - 16]` are xored with `0xB3` then checked if they are equal with `*((_BYTE *)&v28 + v21 + 7)` and `*((_BYTE *)&v29 + v21)` respectively or not. 

However, I tried to examine `v28` and `v29` but they do not point to sthg special. Now I noticed that the variables `v31`, `v32`, and `v33` point to something intersting.

<img width="634" height="112" alt="image" src="https://github.com/user-attachments/assets/d7c373fb-243a-4f22-a8e0-abafc914a471" />

When I examine the stack position of these variables, I found that:

```text
v31              → rsp + 40h    (store 32 bytes of data)
v32              → rsp + 60h    (store 16 bytes of data)
v33              → rsp + 70h    (store 16 bytes of data)

v28              → rsp + 28h
v29              → rsp + 30h

With v21 = 17
&v28 + v21 + 7   → rsp + 40h     → v31 + 0h
&v29 + v21       → rsp + 41h     → v31 + 1h
```

With the increasing by `2` of `v21` after each iteration, each character of the `input` from the first one is compared with a byte in a array made by `v33`, `v32` and `v31` when xored with `0xB3`.

Now we just need to decode the array formed by `v33`, `v32` and `v31`.

```text
v31    →     F1F8E0F6F0C8C1C686C7ECC980C183ECC3C4DD80D7ECD6D784D28AD683D78685 (rsp + 40h → rsp + 5Fh)
v32    →     0D78087D18B8481D286D085D6D1D281D2h                               (rsp + 60h → rsp + 6Fh)
v33    →     0CED181D2D580D0838B8284D0808BD580h                               (rsp + 70h → rsp + 7Fh)
```

The data hold by `v32` and `v33` is displayed as hex so we need to reverse it by bytes due to little endian.

```text
v31    →     F1 F8 E0 F6 F0 C8 C1 C6 86 C7 EC C9 80 C1 83 EC C3 C4 DD 80 D7 EC D6 D7 84 D2 8A D6 83 D7 86 85 (rsp + 40h → rsp + 5Fh)
v32    →     D2 81 D2 D1 D6 85 D0 86 D2 81 84 8B D1 87 80 D7                                                 (rsp + 60h → rsp + 6Fh)
v33    →     80 D5 8B 80 D0 84 82 8B 83 D0 80 D5 D2 81 D1 CE                                                 (rsp + 70h → rsp + 7Fh)
```

Finally we just need to xor each of these with `0xB3`, translate each byte to ASCII character and get the flag.

## Key Takeaways

At first I was quite struggling when examine `v28` and `v29` to find the resources that they point to and ignored `v31`, `v32`, and `v33` just because they are not called in the checker loop. So that beware when simplizing the decomplied code, we may missed something valuable.

## References

- [BKSEC Training](https://training.bksec.vn/)
