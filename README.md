### Intel.AES-NI.CBC: Implementing AES-256 encryption in CBC mode using Intel's AES-NI intrinsics

AES-NI instructions run at hardware speed, often several times faster than a pure-software AES implementation. For demonstration, the following image shows a side-by-side benchmark of [tiny-AES-c](https://github.com/kokke/tiny-AES-c) versus our AES-NI implementation:

</br>

![image](https://github.com/user-attachments/assets/107adf51-601c-4f26-82ac-b6aaefe30757)


</br>
